#include <stdlib.h>
#include <nfc/nfc.h>

/*  Print uint8_t array data in hex string
 */
static void print_hex(const uint8_t *pbtData, const size_t szBytes)
{
	size_t szPos;

	for(szPos = 0; szPos < szBytes; szPos++)
	{
		printf("%02x ",pbtData[szPos]);
	}
	printf("\n");
}

int main(int argc, const char *argv[])
{
	nfc_device *pnd;
	nfc_target nt;
	nfc_context *context;

	// initialize the driver
	nfc_init(&context);

	if(context == NULL)
	{
		printf("Unable to init libnfc (malloc)\n");
		exit(EXIT_FAILURE);
	}

	// open device
	pnd = nfc_open(context, NULL);

	if(pnd == NULL) {
		printf("ERR: Unable to open NFC device");
	    nfc_exit(context);
		exit(EXIT_FAILURE);
	}

	// initialize the initiator
	if(nfc_initiator_init(pnd) < 0)
	{
		nfc_perror(pnd, "nfc_initiator_init");
	    nfc_exit(context);
		exit(EXIT_FAILURE);
	}

	printf("NFC reader: %s opened\n", nfc_device_get_name(pnd));

	// poll for a MIFARE tag
	const nfc_modulation nmMifare = {
		.nmt = NMT_ISO14443A,
		.nbr = NBR_106,
	};

	if(nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt) > 0)
	{
		printf("ISO14443A tag was found:\n");
		printf("\tATQS (SENS_RES): ");
		print_hex(nt.nti.nai.abtAtqa, 2);
		printf("\tUID (NFCID%c): ", (nt.nti.nai.abtUid[0] == 0x08 ? '3':'1'));
		print_hex(nt.nti.nai.abtUid, nt.nti.nai.szUidLen);
		printf("\tSAK (SEL_RES): ");
		print_hex(&nt.nti.nai.btSak, 1);

		if(nt.nti.nai.szAtsLen)
		{
			printf("\t\tATS (ATR): ");
			print_hex(nt.nti.nai.abtAts, nt.nti.nai.szAtsLen);
		}
	}

	// close the device
	nfc_close(pnd);

	// release the context
	nfc_exit(context);
	exit(EXIT_SUCCESS);

}

