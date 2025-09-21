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

package hypervisors

import (
	"fmt"
	"path/filepath"
	"syscall"

	"github.com/urunc-dev/urunc/pkg/unikontainers/unikernels"
)

const (
	CloudHypervisorVmm    VmmType = "cloud-hypervisor"
	CloudHypervisorBinary string  = "cloud-hypervisor"
)

type CloudHypervisor struct {
	binaryPath string
	binary     string
}

func (ch *CloudHypervisor) Stop(_ string) error {
	return nil
}

func (ch *CloudHypervisor) Ok() error {
	return nil
}

func (ch *CloudHypervisor) UsesKVM() bool {
	return true
}

func (ch *CloudHypervisor) SupportsSharedfs() bool {
	return true
}

func (ch *CloudHypervisor) Path() string {
	return ch.binaryPath
}

func (ch *CloudHypervisor) Execve(args ExecArgs, unikernel unikernels.Unikernel) error {
	apiSocketPath := filepath.Join("/temp", args.Container+"-ch.sock")
	cmd := []string{
		ch.Path(),
		"--api-socket",
		apiSocketPath,
	}

	cmd = append(cmd, "--cpus", "boot=1")

	// Add memory
	mem := DefaultMemory
	if args.MemSizeB != 0 {
		mem = bytesToMiB(args.MemSizeB)
		if mem == 0 {
			mem = DefaultMemory
		}
	}
	memStr := fmt.Sprintf("size=%dM", mem)
	cmd = append(cmd, "--memory", memStr)

	cmd = append(cmd, "--kernel", args.UnikernelPath)

	cmd = append(cmd, "--cmdline", args.Command)

	if args.TapDevice != "" {
		netStr := fmt.Sprintf("tap=%s", args.TapDevice)
		if args.GuestMAC != "" {
			netStr += fmt.Sprintf(",mac=%s", args.GuestMAC)
		}
		cmd = append(cmd, "--net", netStr)
	}

	if args.BlockDevice != "" {
		cmd = append(cmd, "--disk", fmt.Sprintf("path=%s", args.BlockDevice))
	}

	vmmLog.WithField("Cloud-hypervisor command", cmd).Debug("Ready to execve Cloud-hypervisor")
	return syscall.Exec(ch.Path(), cmd, args.Environment) //nolint: gosec

}
