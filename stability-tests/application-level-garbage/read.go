package main

import (
	"encoding/json"

	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/stability-tests/common"
	"github.com/pkg/errors"
)

var blockBuffer []byte

func readBlocks() (<-chan *externalapi.DomainBlock, error) {
	c := make(chan *externalapi.DomainBlock)

	spawn("applicationLevelGarbage-readBlocks", func() {
		lineNum := 0
		for blockJSON := range common.ScanFile(activeConfig().BlocksFilePath) {
			domainBlock := &externalapi.DomainBlock{}

			err := json.Unmarshal(blockJSON, domainBlock)
			if err != nil {
				panic(errors.Wrapf(err, "error deserializing line No. %d with json %s", lineNum, blockJSON))
			}

			c <- domainBlock
		}
		close(c)
	})

	return c, nil
}
