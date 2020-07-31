//+build linux_bpf

package bytecode

import (
	"github.com/DataDog/ebpf/manager"
)

type PerfHandler struct {
	ClosedChannel chan []byte
	LostChannel   chan uint64
}

func NewPerfHandler(closedChannelSize int) *PerfHandler {
	return &PerfHandler{
		ClosedChannel: make(chan []byte, closedChannelSize),
		LostChannel:   make(chan uint64, 10),
	}
}

func (c *PerfHandler) dataHandler(CPU int, batchData []byte, perfMap *manager.PerfMap, manager *manager.Manager) {
	c.ClosedChannel <- batchData
}

func (c *PerfHandler) lostHandler(CPU int, lostCount uint64, perfMap *manager.PerfMap, manager *manager.Manager) {
	c.LostChannel <- lostCount
}