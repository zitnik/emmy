package mobile

import (
	"github.com/xlab-si/emmy/client"
	"github.com/xlab-si/emmy/types"
)

func GetServiceInfo(endpoint string) (*types.ServiceInfo, error) {
	conn, err := client.GetConnection(endpoint, "", true)
	if err != nil {
		return nil, err
	}

	info, err := client.GetServiceInfo(conn)
	if err != nil {
		return nil, err
	}

	return info, nil
}
