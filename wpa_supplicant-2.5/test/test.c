#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include "wpa_ctrl.h"

size_t os_strlen(const char *s)
{
        const char *p = s;
        while (*p)
                p++;
        return p - s;
}

static int wpa_request(struct wpa_ctrl* ctrl, char* cmd)
{
	char buf[4096];
	size_t len = sizeof(buf) - 1;
	int ret;

	ret = wpa_ctrl_request(ctrl, cmd, os_strlen(cmd), buf, &len, NULL);

	if (ret == -2)
	{
		printf("wpa_request time out\n");
		return -2;
	} else if (ret < 0){
		printf("wpa_request error send or receive\n");
		return -1;
	} else {
		buf[len] = '\0';
		printf("%s\n", buf);
	}
	return 0;	
}

static int wpa_recv_msg(struct wpa_ctrl *mon)
{
	int ret;

	ret = wpa_ctrl_attach(mon);
	
	if (ret == -2)
	{
		printf("wpa_recv time out\n");
		return -2;
	} else if (ret < 0){
		printf("wpa_recv error \n");
		return -1;
	} else {
		while(wpa_ctrl_pending(mon) > 0)
		{
			char buf[4096];
			size_t len = sizeof(buf) - 1;
			if(wpa_ctrl_recv(mon, buf, &len) == 0)
			{
				buf[len] = '\0';
				printf("message: %s\n", buf);
			} else {
				printf("could not read pending message\n");
			}
		}
	}
	wpa_ctrl_detach(mon);
	return 0;
}
int main (int argc, char argv[])
{
	struct	wpa_ctrl *ctrl_conn = NULL;
	struct	wpa_ctrl *mon_conn = NULL;
	
	ctrl_conn = wpa_ctrl_open("/var/run/wpa_supplicant/wlan0");
	mon_conn = wpa_ctrl_open("/var/run/wpa_supplicant/wlan0");

	if ((ctrl_conn == NULL) || (mon_conn == NULL))
	{
		printf("failed to connect wpa_supplicant\n");
	}
	else
	{
		printf("successfully to connect to wpa_supplicant\n");
	}

	wpa_request(ctrl_conn, "STATUS");
	wpa_recv_msg(mon_conn);
	wpa_request(ctrl_conn, "SCAN");
	wpa_recv_msg(mon_conn);
	wpa_request(ctrl_conn, "BSS 48:f8:b3:ce:4e:36");

	wpa_ctrl_close(ctrl_conn);
	wpa_ctrl_close(mon_conn);
	return 0;
}
