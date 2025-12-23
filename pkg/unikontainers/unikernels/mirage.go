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
	"debug/elf"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/urunc-dev/urunc/pkg/unikontainers/types"
)

const (
	MirageUnikernel    string = "mirage"
	AnnotationNetMap          = "urunc.dev/mirage-net-map"
	AnnotationBlockMap        = "urunc.dev/mirage-block-map"
)

type Mirage struct {
	Command     string
	Monitor     string
	Net         MirageNet
	Block       []MirageBlock
	BinaryPath  string
	Manifest    *Solo5Manifest
	Annotations map[string]string
}

type Solo5Manifest struct {
	Devices []Solo5Device `json:"devices"`
}

type Solo5Device struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type MirageNet struct {
	Address string
	Gateway string
}

type MirageBlock struct {
	ID       string
	HostPath string
}

func (m *Mirage) CommandString() (string, error) {
	return fmt.Sprintf("%s %s %s", m.Net.Address,
		m.Net.Gateway,
		m.Command), nil
}

func (m *Mirage) SupportsBlock() bool {
	return true
}

func (m *Mirage) SupportsFS(_ string) bool {
	return false
}

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

func (m *Mirage) MonitorBlockCli() []types.MonitorBlockArgs {
	if len(m.Block) == 0 {
		return nil
	}
	switch m.Monitor {
	case "hvt", "spt":
		// TODO: Explore options for multiple block devices in MirageOS
		// over Solo5-spt and Solo5-hvt. Solo5 expects to use as an ID
		// a specific name which the guest is also aware of in order to
		// attach the respective block. As a result, urunc needs to know
		// the correct ID to set, which is not straightforward. Therefore,
		// there are two options. Either we read the Solo5 manifest or,
		// we require specific IDs. Till we decide about that, we will
		// use a single block device. We also need to find some use cases
		// where multiple block devices are configured in MirageOS and check
		// how MirageOS handles/configures them.
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

func (m *Mirage) MonitorCli() types.MonitorCliArgs {
	return types.MonitorCliArgs{}
}

// getMirageDeviceName determines the correct Solo5 interface name.
func (m *Mirage) getMirageDeviceName(hostDev string, devType string, defaultName string) string {
	// 1. Check Annotations
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
				return mirageName
			}
		}
	}

	// 2. Check Manifest (Auto-detect if only one device exists)
	if m.Manifest != nil {
		var validDevs []string
		for _, dev := range m.Manifest.Devices {
			if dev.Type == devType {
				validDevs = append(validDevs, dev.Name)
			}
		}
		if len(validDevs) == 1 {
			return validDevs[0]
		}
	}

	// 3. Fallback
	return defaultName
}

// parseSolo5Manifest extracts the .note.solo5.manifest section from the ELF
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

	var manifest Solo5Manifest
	// Attempt to find the start of the JSON object '{'
	jsonStart := strings.Index(string(data), "{")
	if jsonStart == -1 {
		return nil, fmt.Errorf("invalid manifest format")
	}

	if err := json.Unmarshal(data[jsonStart:], &manifest); err != nil {
		return nil, err
	}

	return &manifest, nil
}

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
