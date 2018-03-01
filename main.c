/***************************************************************************
* Description: Detect WOL Magic Packet and send SMS-
* Notice of it.
* Author: DarkCat
* License: GNU GPL
* Version: Demo
* gcc -lpcap -lcurl main.c -o msniff
*
 ***************************************************************************/
#include <stdio.h>
#include <pcap.h>
#include <curl/curl.h>

void got_packet	(
			u_char *args,
			const struct pcap_pkthdr *header,
			const u_char *packet
		);
int main() {
   const u_char *packet;
   struct pcap_pkthdr header;
	 pcap_t *handle;
	 char dev[] = "enp3s0";
	 char errbuf[PCAP_ERRBUF_SIZE];
	 struct bpf_program fp;
	 char filter_exp[] = "ether proto 0x0842";
	 bpf_u_int32 mask;
	 bpf_u_int32 net;

	 if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		 fprintf(stderr, "Can't get netmask for device %s\n", dev);
		 net = 0;
		 mask = 0;
	 }

   handle = pcap_open_live(dev, BUFSIZ, 1, 10000, errbuf);

   if (handle == NULL) {
		 fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		 return(2);
	 }
	 if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		 fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		 return(2);
	 }
	 if (pcap_setfilter(handle, &fp) == -1) {
		 fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		 return(2);
	 }
  void callback (u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*
         packet)
			 {
				static int count = 1;
			 	fprintf(stdout, "%3d, ", count);
			 	fflush(stdout);
			 if (count++ > 11) {
			 	  CURL *curl = curl_easy_init();
          curl_easy_setopt(curl, CURLOPT_URL,
          "https://sms.ru/sms/send?api_id=API_KEY&to=phone_number&msg=WOL_storm");
          curl_easy_perform(curl);
			 }
			}

      packet = pcap_next(handle, &header);

      pcap_loop(handle, -1, callback, NULL);


     pcap_close(handle);
return 0;
}
