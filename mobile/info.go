package mobile

import (
	"github.com/xlab-si/emmy/client"
)

func GetServiceInfo(endpoint string) (*ServiceInfo, error) {
	conn, err := client.GetConnection(endpoint, "", true)
	if err != nil {
		return nil, err
	}

	info, err := client.GetServiceInfo(conn)
	if err != nil {
		return nil, err
	}

	serviceInfo := NewServiceInfo(info.Name, info.Description, info.Provider)
	return serviceInfo, nil
}
