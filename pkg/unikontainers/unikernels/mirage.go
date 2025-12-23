// Copyright (c) 2023-2025, Nubificus LTD
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package unikernels

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/urunc-dev/urunc/pkg/unikontainers/types"
)

const (
	// MirageUnikernel is the unikernel type for MirageOS
	MirageUnikernel string = "mirage"
	// AnnotationNetMap is the annotation key for network device mapping
	AnnotationNetMap string = "urunc.dev/mirage-net-map"
	// AnnotationBlockMap is the annotation key for block device mapping
	AnnotationBlockMap string = "urunc.dev/mirage-block-map"
)

// Constants from solo5 mft_abi.h
const (
	mftDevBlockBasic = 0
	mftDevNetBasic   = 1
	mftNameMax       = 64
)

// Regular expression to validate device names (alphanumeric + underscore)
var validDeviceName = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

// Mirage represents a MirageOS unikernel configuration
type Mirage struct {
	Command     string
	Monitor     string
	Net         MirageNet
	Block       []MirageBlock
	BinaryPath  string
	Manifest    *Solo5Manifest
	Annotations map[string]string
}

// Solo5Manifest represents the parsed devices from the unikernel binary
type Solo5Manifest struct {
	Devices []Solo5Device
}

// Solo5Device represents a single device entry in the manifest
type Solo5Device struct {
	Name string
	Type string
}

// MftHeader matches the 12-byte header found in the binary.
// 0x00: Pad/Reserved (4)
// 0x04: Version (4)
// 0x08: Entries (4)
type MftHeader struct {
	Pad     uint32
	Version uint32
	Entries uint32
}

// MftEntry matches the 104-byte stride.
// Name (65) + Pad (7) = 72
// Type (8) = 80
// Flags (8) = 88
// Pad2 (16) = 104
// NOTE: All fields MUST be exported (Capitalized) for binary.Read to work.
type MftEntry struct {
	Name  [mftNameMax + 1]byte
	Pad   [7]byte // Exported to avoid panic in binary.Read
	Type  uint64
	Flags uint64
	Pad2  [16]byte // Exported to avoid panic in binary.Read
}

// MirageNet holds network configuration
type MirageNet struct {
	Address string
	Gateway string
}

// MirageBlock holds block device configuration
type MirageBlock struct {
	ID       string
	HostPath string
}

// CommandString returns the command line arguments for the unikernel
func (m *Mirage) CommandString() (string, error) {
	return fmt.Sprintf("%s %s %s", m.Net.Address,
		m.Net.Gateway,
		m.Command), nil
}

// SupportsBlock returns true as Mirage supports block devices
func (m *Mirage) SupportsBlock() bool {
	return true
}

// SupportsFS returns false as Mirage does not support filesystem passthrough
func (m *Mirage) SupportsFS(_ string) bool {
	return false
}

// MonitorNetCli returns the network arguments for the monitor
func (m *Mirage) MonitorNetCli(ifName string, mac string) string {
	switch m.Monitor {
	case "hvt", "spt":
		mirageID := m.getMirageDeviceName(ifName, "NET_BASIC", "service")

		netOption := fmt.Sprintf("--net:%s=%s", mirageID, ifName)
		netOption += fmt.Sprintf(" --net-mac:%s=%s", mirageID, mac)
		return netOption
	default:
		return ""
	}
}

// MonitorBlockCli returns the block device arguments for the monitor
func (m *Mirage) MonitorBlockCli() []types.MonitorBlockArgs {
	if len(m.Block) == 0 {
		return nil
	}
	switch m.Monitor {
	case "hvt", "spt":
		var blockArgs []types.MonitorBlockArgs

		for i, blk := range m.Block {
			defaultName := "storage"
			if i > 0 {
				defaultName = fmt.Sprintf("storage%d", i)
			}

			mirageID := m.getMirageDeviceName(blk.ID, "BLOCK_BASIC", defaultName)

			blockArgs = append(blockArgs, types.MonitorBlockArgs{
				ID:   mirageID,
				Path: blk.HostPath,
			})
		}
		return blockArgs
	default:
		return nil
	}
}

// MonitorCli returns general monitor arguments
func (m *Mirage) MonitorCli() types.MonitorCliArgs {
	return types.MonitorCliArgs{}
}

// getMirageDeviceName determines the correct Solo5 interface name.
func (m *Mirage) getMirageDeviceName(hostDev string, devType string, defaultName string) string {
	resolvedName := ""

	// 1. Check Annotations first
	var mapKey string
	if devType == "NET_BASIC" {
		mapKey = AnnotationNetMap
	} else {
		mapKey = AnnotationBlockMap
	}

	if val, ok := m.Annotations[mapKey]; ok {
		var mapping map[string]string
		if err := json.Unmarshal([]byte(val), &mapping); err == nil {
			if mirageName, found := mapping[hostDev]; found {
				resolvedName = mirageName
			}
		}
	}

	// 2. If not found in annotations, check Manifest (Auto-detect if only one device exists)
	if resolvedName == "" && m.Manifest != nil {
		var validDevs []string
		for _, dev := range m.Manifest.Devices {
			if dev.Type == devType {
				validDevs = append(validDevs, dev.Name)
			}
		}
		if len(validDevs) == 1 {
			resolvedName = validDevs[0]
		}
	}

	// 3. Fallback
	if resolvedName == "" {
		resolvedName = defaultName
	}

	// Security check: ensure the name is safe
	if !validDeviceName.MatchString(resolvedName) {
		// Log warning here if logger is available
		return defaultName
	}
	return resolvedName
}

func parseSolo5ManifestData(data []byte) (*Solo5Manifest, error) {
	// Offset logic based on binary analysis:
	// 0x00-0x13: ELF Note Header
	// 0x14: Start of MftHeader (Pad=0, Ver=1, Ent=2)

	var offset int64

	// Heuristic to skip ELF Note Header
	if len(data) > 12 {
		var namesz uint32
		// FIX: Checked error return value (errcheck warning)
		if err := binary.Read(bytes.NewReader(data[0:4]), binary.LittleEndian, &namesz); err != nil {
			// If we can't even read 4 bytes, just ignore this check and use offset 0
		} else {
			// If namesz is 6 ("Solo5\0"), skip header.
			// Header = 12 + aligned(namesz)
			if namesz == 6 {
				offset = int64(12 + ((namesz + 3) &^ 3))
			}
		}
	}

	r := bytes.NewReader(data)
	if _, err := r.Seek(offset, 0); err != nil {
		return nil, err
	}

	var header MftHeader
	if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
		return nil, fmt.Errorf("failed to read mft header: %v", err)
	}

	// Sanity Check
	if header.Version != 1 {
		return nil, fmt.Errorf("invalid manifest version: %d (expected 1)", header.Version)
	}

	manifest := &Solo5Manifest{}

	for i := 0; i < int(header.Entries); i++ {
		var entry MftEntry
		if err := binary.Read(r, binary.LittleEndian, &entry); err != nil {
			break
		}

		// Clean C-String (remove null bytes)
		nameLen := bytes.IndexByte(entry.Name[:], 0)
		if nameLen < 0 {
			nameLen = len(entry.Name)
		}
		cleanName := string(entry.Name[:nameLen])

		// Skip empty names (often internal devices)
		if cleanName == "" {
			continue
		}

		var devType string
		switch entry.Type {

		case mftDevNetBasic:
			devType = "NET_BASIC"
		case mftDevBlockBasic:
			devType = "BLOCK_BASIC"
		default:
			devType = fmt.Sprintf("UNKNOWN_%d", entry.Type)
		}

		manifest.Devices = append(manifest.Devices, Solo5Device{
			Name: cleanName,
			Type: devType,
		})
	}

	return manifest, nil
}

// getSolo5Manifest extracts the .note.solo5.manifest section from the ELF
func getSolo5Manifest(path string) (*Solo5Manifest, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	section := f.Section(".note.solo5.manifest")
	if section == nil {
		return nil, fmt.Errorf("no solo5 manifest section found")
	}

	data, err := section.Data()
	if err != nil {
		return nil, err
	}

	return parseSolo5ManifestData(data)
}

// Init initializes the Mirage configuration
func (m *Mirage) Init(data types.UnikernelParams) error {

	m.BinaryPath = data.UnikernelPath
	m.Annotations = data.Annotations
	if manifest, err := getSolo5Manifest(m.BinaryPath); err == nil {
		m.Manifest = manifest
	}

	if data.Net.Mask != "" {
		m.Net.Address = "--ipv4=" + data.Net.IP + "/24"
		m.Net.Gateway = "--ipv4-gateway=" + data.Net.Gateway
	}
	m.Block = make([]MirageBlock, 0, len(data.Block))
	for _, blk := range data.Block {
		newBlk := MirageBlock{
			ID:       blk.ID,
			HostPath: blk.Source,
		}
		m.Block = append(m.Block, newBlk)
	}

	m.Command = strings.Join(data.CmdLine, " ")
	m.Monitor = data.Monitor

	return nil
}

func newMirage() *Mirage {
	mirageStruct := new(Mirage)
	return mirageStruct
}
