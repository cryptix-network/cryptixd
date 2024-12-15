package main

import (
	"context"
	"fmt"

	"github.com/cryptix-network/cryptixd/cmd/cryptixwallet/daemon/client"
	"github.com/cryptix-network/cryptixd/cmd/cryptixwallet/daemon/pb"
	"github.com/cryptix-network/cryptixd/cmd/cryptixwallet/utils"
)

func balance(conf *balanceConfig) error {
	daemonClient, tearDown, err := client.Connect(conf.DaemonAddress)
	if err != nil {
		return err
	}
	defer tearDown()

	ctx, cancel := context.WithTimeout(context.Background(), daemonTimeout)
	defer cancel()
	response, err := daemonClient.GetBalance(ctx, &pb.GetBalanceRequest{})
	if err != nil {
		return err
	}

	pendingSuffix := ""
	if response.Pending > 0 {
		pendingSuffix = " (pending)"
	}
	if conf.Verbose {
		pendingSuffix = ""
		println("Address                                                                       Available             Pending")
		println("-----------------------------------------------------------------------------------------------------------")
		for _, addressBalance := range response.AddressBalances {
			fmt.Printf("%s %s %s\n", addressBalance.Address, utils.FormatCytx(addressBalance.Available), utils.FormatCytx(addressBalance.Pending))
		}
		println("-----------------------------------------------------------------------------------------------------------")
		print("                                                 ")
	}
	fmt.Printf("Total balance, CYTX %s %s%s\n", utils.FormatCytx(response.Available), utils.FormatCytx(response.Pending), pendingSuffix)

	return nil
}
