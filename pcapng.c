#include "pcapfix.h"
#include "pcapng.h"

/* Header of all pcapng blocks */
struct block_header {
	u_int32_t	block_type;    /* block type */
	u_int32_t	total_length;  /* block length */
};

/* Header of all pcapng options */
struct option_header {
	u_short		option_code;    /* option code - depending of block (0 - end of opts, 1 - comment are in common) */
	u_short		option_length;  /* option length - length of option in bytes (will be padded to 32bit) */
};

/* Section Header Block (SHB) - ID 0x0A0D0D0A */
struct section_header_block {
	u_int32_t	byte_order_magic; /* byte order magic - indicates swapped data */
	u_short		major_version;    /* major version of pcapng (1 atm) */
	u_short		minor_version;    /* minor version of pcapng (0 atm) */
	int64_t	section_length;   /* length of section - can be -1 (parsing necessary) */
};

/* Interface Description Block (IDB) - ID 0x00000001 */
struct interface_description_block {
	u_short		linktype;   /* the link layer type (was -network- in classic pcap global header) */
	u_short		reserved;   /* 2 bytes of reserved data */
	u_int32_t	snaplen;    /* maximum number of bytes dumped from each packet (was -snaplen- in classic pcap global header */
};

/* Packet Block (PB) - ID 0x00000002 (OBSOLETE - EPB should be used instead) */
struct packet_block {
	u_short		interface_id;   /* the interface the packet was captured from - identified by interface description block in current section */
	u_short		drops_count;    /* packet dropped by IF and OS since prior packet */
	u_int32_t	timestamp_high; /* high bytes of timestamp */
	u_int32_t	timestamp_low;  /* low bytes of timestamp */
	u_int32_t	caplen;         /* length of packet in the capture file (was -incl_len- in classic pcap packet header) */
	u_int32_t	len;            /* length of packet when transmitted (was -orig_len- in classic pcap packet header) */
};

/* Simple Packet Block (SPB) - ID 0x00000003 */
struct simple_packet_block {
	u_int32_t	len;  /* length of packet when transmitted (was -orig_len- in classic pcap packet header) */
};

/* Name Resolution Block (NRB) - ID 0x00000004 */
struct name_resolution_block {
	u_short		record_type;    /* type of record (ipv4 / ipv6) */
	u_short		record_length;  /* length of record value */
};

/* Interface Statistics Block - ID 0x00000005 */
struct interface_statistics_block {
	u_int32_t	interface_id;     /* the interface the stats refer to - identified by interface description block in current section */
	u_int32_t	timestamp_high;   /* high bytes of timestamp */
	u_int32_t	timestamp_low;    /* low bytes of timestamp */
};

/* Enhanced Packet Block (EPB) - ID 0x00000006 */
struct enhanced_packet_block {
	u_int32_t	interface_id;     /* the interface the packet was captured from - identified by interface description block in current section */
	u_int32_t	timestamp_high;   /* high bytes of timestamp */
	u_int32_t	timestamp_low;    /* low bytes of timestamp */
	u_int32_t	caplen;           /* length of packet in the capture file (was -incl_len- in classic pcap packet header) */
	u_int32_t	len;              /* length of packet when transmitted (was -orig_len- in classic pcap packet header) */
};

/*
 * Function:  fix_pcapng
 * ---------------------
 * tries to fix a pcapng file
 *
 * pcap:      file pointer to input file
 * pcap_fix:  file pointer to output file
 *
 * returns: >0   success (number of corruptions fixed)
 *           0   success (nothing to fix)
 *          -1   error (not a pcap file)
 *          -2   error (unable to repair)
 *          -3   error (EOF while reading input file)
 *
 */
int fix_pcapng(FILE *pcap, FILE *pcap_fix) {
  struct block_header bh;                   /* Block Header */
  struct option_header oh;                  /* Option Header */
  struct section_header_block shb;          /* Section Header Block */
  struct interface_description_block idb;   /* Interface Description Block */
  struct packet_block pb;                   /* Packet Block */
  struct simple_packet_block spb;           /* Simple Packet Block */
  struct name_resolution_block nrb;         /* Name Resolution Block */
  struct interface_statistics_block isb;    /* Interface Statistics Block */
  struct enhanced_packet_block epb;         /* Enhanced Packet Block */

  char *data;                               /* Storage for packet data */
  char *new_block;                          /* Storage for new (maybe repaired) block to finally write into ouput file */

  unsigned int block_pos;                   /* current position inside -new_block- to write further data to */
  unsigned long bytes;                      /* written bytes/blocks counter */
  unsigned int check;                       /* variable to check end of blocks sizes */
  unsigned long padding;                    /* calculation for padding bytes */
  unsigned long pos;                        /* current block position in input file */
  unsigned long filesize;                   /* size of input file */
  signed long left;                         /* bytes left to proceed until current blocks end is reached */
  unsigned int count;
  unsigned int shb_num;
  unsigned int idb_num;
  int fixes;
  int res;

  /* get file size of input file */
  fseek(pcap, 0, SEEK_END);
  filesize = ftell(pcap);
  fseek(pcap, 0, SEEK_SET);

  /* init positon of current block */
  pos = 0;
  fixes = 0;
  shb_num = 0;
  idb_num = 0;

  /* loop every block inside pcapng file until end of file is reached */
  while (pos < filesize) {
    /* read the header of the current block */
    bytes = fread(&bh, sizeof(bh), 1, pcap);
    if (bytes != 1) return -3;

    if (bh.total_length > filesize-pos) {
      if (verbose) printf("[-] Block Length (%u) exceeds file size (%ld).\n", bh.total_length, filesize);

      /* search for next valid block */
      if (verbose) printf("[*] Trying to align next block...\n");
      res = find_valid_block(pcap, filesize);
      if (res == 0) {
        if (verbose) printf("[+] GOT Next Block at Position %ld\n", ftell(pcap));
        bh.total_length = ftell(pcap)-pos;
      } else {
        if (verbose) printf("[*] No more valid Blocks found inside file! (maybe it was the last one)\n");
        bh.total_length = filesize-pos;
      }
      if (verbose) printf("[*] Assuming this blocks size as %u bytes.\n", bh.total_length);
      fseek(pcap, pos+sizeof(struct block_header), SEEK_SET);

      if (verbose == 0) printf("[-] Invalid Block size => CORRECTED.\n");

      fixes++;
    }

    /* how many bytes are left until the final block size (end of block) is reached */
    left = bh.total_length-sizeof(bh)-sizeof(check);

    /* allocate memory for the new block - that will be written to repaired output file finally */
    new_block = malloc(bh.total_length);

    /* copy the current blocks header into repaired block */
    memcpy(new_block, &bh, 8);
    block_pos = 8;

    /* what is the type of block at current position ? */
    switch (bh.block_type) {

      /* Section Header Block */
      case TYPE_SHB:
        if (verbose) printf("[*] FOUND: Section Header Block: 0x%08x (%u bytes)\n", bh.block_type, bh.total_length);

        /* read section header block into struct */
        bytes = fread(&shb, sizeof(shb), 1, pcap);
        if (bytes != 1) return -3;
        left -= sizeof(shb);

        /* check for pcap's magic bytes () */
        if (shb.byte_order_magic == BYTE_ORDER_MAGIC) {
          if (verbose) printf("[+] Byte Order Magic: 0x%x\n", shb.byte_order_magic);
        } else if (shb.byte_order_magic == htonl(BYTE_ORDER_MAGIC)) {
          if (verbose) printf("[+] Byte Order Magic: 0x%x (SWAPPED)\n", shb.byte_order_magic);
          swapped = 1;
        } else {
          printf("[-] Unknown Byte Order Magic: 0x%x ==> CORRECTED.\n", shb.byte_order_magic);
          shb.byte_order_magic = BYTE_ORDER_MAGIC;
          fixes++;
        }

        /* check for major version number (2) */
        if (conshort(shb.major_version) == 1) {	/* current major version is 2 */
          if (verbose) printf("[+] Major version number: %hu\n", conshort(shb.major_version));
        } else {
          printf("[-] Major version number: %hu ==> CORRECTED.\n", conshort(shb.major_version));
          shb.major_version = conshort(1);
          fixes++;
        }

        /* check for minor version number */
        if (conshort(shb.minor_version) == 0) {	/* current minor version is 4 */
          if (verbose) printf("[+] Minor version number: %hu\n", conshort(shb.minor_version));
        } else {
          printf("[-] Minor version number: %hu ==> CORRECTED.\n", conshort(shb.minor_version));
          shb.minor_version = conshort(0);
          fixes++;
        }

        /* section length */
        if (shb.section_length == -1) {
          if (verbose) printf("[*] Section length: %ld\n", shb.section_length);

        } else {
          if (verbose) printf("[*] Section length: %ld ==> SETTING TO -1\n", shb.section_length);
          shb.section_length = -1;
        }

        /* copy section header block into repaired block */
        memcpy(new_block+block_pos, &shb, sizeof(shb));
        block_pos += sizeof(shb);

        /* options */
        count = 0 ;
        while (left > 0) {

          /* read option header into struct */
          bytes = fread(&oh, sizeof(oh), 1, pcap);
          if (bytes != 1) return -3;
          left -= sizeof(oh);

          /* which option did we get ? */
          switch (oh.option_code) {
            /* End of Options */
            case 0x00:
              if (verbose >= 2) printf("[+] OPTION: End of Options... (%u bytes)\n", oh.option_length);
              break;
            /* Comment Option */
            case 0x01:
              if (verbose >= 2) printf("[+] OPTION: Comment... (%u bytes)\n", oh.option_length);
              break;
            /* Hardware Information */
            case 0x02:
              if (verbose >= 2) printf("[+] OPTION: Hardware... (%u bytes)\n", oh.option_length);
              break;
            /* Operating System Information */
            case 0x03:
              if (verbose >= 2) printf("[+] OPTION: Operating System... (%u bytes)\n", oh.option_length);
              break;
            /* User Application Information */
            case 0x04:
              if (verbose >= 2) printf("[+] OPTION: Userappl... (%u bytes)\n", oh.option_length);
              break;
          }

          /* Invalid Option? */
          if (oh.option_code > 0x04) {
            printf("[-] Unknown option code: 0x%04x (%u bytes) ==> SKIPPING.\n", oh.option_code, oh.option_length);

            fixes++;

            if (count == 0) {
              if (verbose) printf("[*] No Options inside -> no need for End of Options...\n");
              break;
            }

            if (verbose) printf("[*] %u Options inside -> Finishing with End of Options...\n", count);

            oh.option_code = 0x00;
            oh.option_length = 0x00;
          }

          /* option is valid */

          /* copy option header into repaired block */
          memcpy(new_block+block_pos, &oh, sizeof(oh));
          block_pos += sizeof(oh);

          /* end of options? -> do not write any further */
          if (oh.option_code == 0x00 && oh.option_length == 0x00) break;

          /* calculate padding for current option value */
          padding = oh.option_length;
          if (oh.option_length%4 != 0) padding += (4-oh.option_length%4);

          /* read data of current option */
          data = malloc(padding);
          bytes = fread(data, padding, 1, pcap);
          left -= padding;

          /* write option data to repaired block */
          memcpy(new_block+block_pos, data, padding);
          block_pos += padding;

          /* clean up memory */
          free(data);

          count++;

        }
        break;

      /* Packet Block */
      case TYPE_PB:

        if (shb_num == 0) {
          printf("[-] No Section Block header found ==> CREATING.\n");
          write_shb(pcap_fix);
          shb_num++;
          fixes++;
        }

        if (verbose >= 2) printf("[*] FOUND: Packet Block: 0x%08x (%u bytes)\n", bh.block_type, bh.total_length);

        /* read packet block into struct */
        bytes = fread(&pb, sizeof(pb), 1, pcap);
        if (bytes != 1) return -3;
        left -= sizeof(pb);

        while (pb.interface_id >= idb_num) {
          printf("[-] Missing IDB for Interface #%u ==> CREATING (#%u).\n", pb.interface_id, idb_num);
          write_idb(pcap_fix);
          idb_num++;
          fixes++;
        }

        /* copy packet block into repaired block */
        memcpy(new_block+block_pos, &pb, sizeof(pb));
        block_pos += sizeof(pb);

        /* calculate padding for packet data */
        padding = pb.caplen;
        if (pb.caplen % 4 != 0) padding += (4 - pb.caplen % 4);

        /* read packet data from input file */
        data = malloc(padding);
        bytes = fread(data, padding, 1, pcap);
        left -= padding;

        /* copy packet data into repaired block */
        memcpy(new_block+block_pos, data, padding);
        block_pos += padding;

        /* clean up memory */
        free(data);

        /* options */
        count = 0;
        while (left > 0) {

          /* read options header */
          bytes = fread(&oh, sizeof(oh), 1, pcap);
          if (bytes != 1) return -3;
          left -= sizeof(oh);

          /* which option did we get ? */
          switch (oh.option_code) {
            /* End of Options */
            case 0x00:
              if (verbose >= 2) printf("[+] OPTION: End of Options... (%u bytes)\n", oh.option_length);
              break;
            /* Comment Option */
            case 0x01:
              if (verbose >= 2) printf("[+] OPTION: Comment... (%u bytes)\n", oh.option_length);
              break;
            /* Link Layer Flags */
            case 0x02:
              if (verbose >= 2) printf("[+] OPTION: Link Layer Flags... (%u bytes)\n", oh.option_length);
              break;
            /* Packet Hash */
            case 0x03:
              if (verbose >= 2) printf("[+] OPTION: Packet Hash... (%u bytes)\n", oh.option_length);
              break;
          }

          /* Invalid Option? */
          if (oh.option_code > 0x03) {
            printf("[-] Unknown option code: 0x%04x (%u bytes) ==> SKIPPING.\n", oh.option_code, oh.option_length);

            fixes++;

            if (count == 0) {
              printf("[*] No Options inside -> no need for End of Options...\n");
              break;
            }

            printf("[*] %u Options inside -> Finishing with End of Options...\n", count);

            oh.option_code = 0x00;
            oh.option_length = 0x00;
          }

          /* option is valid */

          /* copy options header into repaired block */
          memcpy(new_block+block_pos, &oh, sizeof(oh));
          block_pos += sizeof(oh);

          /* end of options? -> do not write any further */
          if (oh.option_code == 0x00 && oh.option_length == 0x00) break;

          /* calculate padding for current option value */
          padding = oh.option_length;
          if (oh.option_length%4 != 0) padding += (4-oh.option_length%4);

          /* read data of current option */
          data = malloc(padding);
          bytes = fread(data, padding, 1, pcap);
          left -= padding;

          /* copy option data to repaired block */
          memcpy(new_block+block_pos, data, padding);
          block_pos += padding;

          /* clean up memory */
          free(data);

          count++;
        }
        break;

      /* Simple Packet Block */
      case TYPE_SPB:

        if (shb_num == 0) {
          if (verbose) printf("[-] No Section Block header found ==> CREATING.\n");
          write_shb(pcap_fix);
          shb_num++;
          fixes++;
        }

        if (verbose >= 2) printf("[*] FOUND: Simple Packet Block: 0x%08x (%u bytes)\n", bh.block_type, bh.total_length);

        /* read simple packet block */
        bytes = fread(&spb, sizeof(spb), 1, pcap);
        if (bytes != 1) return -3;
        left -= sizeof(spb);

        /* copy simple packet block into repaired file */
        memcpy(new_block+block_pos, &spb, sizeof(spb));
        block_pos += sizeof(spb);

        /* calculate padding for packet data */
        /* TODO: len is NOT the length of packet inside file (origlen != caplen); we need to calculate caplen using block length (left) */
        padding = spb.len;
        if (spb.len % 4 != 0) padding += (4 - spb.len % 4);

        /* read packet data from input file */
        data = malloc(padding);
        bytes = fread(data, padding, 1, pcap);
        left -= padding;

        /* copy packet data into repaired block */
        memcpy(new_block+block_pos, data, padding);
        block_pos += padding;

        /* clean up memory */
        free(data);

        break;

      /* Interface Description Block */
      case TYPE_IDB:

        if (shb_num == 0) {
          printf("[-] No Section Block header found ==> CREATING.\n");
          write_shb(pcap_fix);
          shb_num++;
          fixes++;
        }

        if (verbose) printf("[*] FOUND: Interface Description Block: 0x%08x (%u bytes)\n", bh.block_type, bh.total_length);

        /* read interface description block */
        bytes = fread(&idb, sizeof(idb), 1, pcap);	/* read first bytes of input file into struct */
        if (bytes != 1) return -3;
        left -= sizeof(idb);

        /* copy interface description block into repaired block */
        memcpy(new_block+block_pos, &idb, sizeof(idb));
        block_pos += sizeof(idb);

        /* options */
        count = 0;
        while (left > 0) {

          /* read options header */
          bytes = fread(&oh, sizeof(oh), 1, pcap);
          if (bytes != 1) return -3;
          left -= sizeof(oh);

          /* which option did we get? */
          switch (oh.option_code) {
            /* End of Options */
            case 0x00:
              if (verbose >= 2) printf("[+] OPTION: End of Options... (%u bytes)\n", oh.option_length);
              break;
            /* Comment Option */
            case 0x01:
              if (verbose >= 2) printf("[+] OPTION: Comment... (%u bytes)\n", oh.option_length);
              break;
            /* Interface Name */
            case 0x02:
              if (verbose >= 2) printf("[+] OPTION: Interface Name... (%u bytes)\n", oh.option_length);
              break;
            /* Interface Description */
            case 0x03:
              if (verbose >= 2) printf("[+] OPTION: Interface Description... (%u bytes)\n", oh.option_length);
              break;
            /* IPv4 Address of Interface */
            case 0x04:
              if (verbose >= 2) printf("[+] OPTION: IPv4 Address... (%u bytes)\n", oh.option_length);
              break;
            /* IPv6 Address of Interface */
            case 0x05:
              if (verbose >= 2) printf("[+] OPTION: IPv6 Address... (%u bytes)\n", oh.option_length);
              break;
            /* MAC Address of Interface */
            case 0x06:
              if (verbose >= 2) printf("[+] OPTION: MAC Address... (%u bytes)\n", oh.option_length);
              break;
            /* EUI Address of Interface */
            case 0x07:
              if (verbose >= 2) printf("[+] OPTION: EUI Address... (%u bytes)\n", oh.option_length);
              break;
            /* Interface Speed */
            case 0x08:
              if (verbose >= 2) printf("[+] OPTION: Interface Speed... (%u bytes)\n", oh.option_length);
              break;
            /* Resolution of Timestamps */
            case 0x09:
              if (verbose >= 2) printf("[+] OPTION: Resolution of Timestamps... (%u bytes)\n", oh.option_length);
              break;
            /* Timezone */
            case 0x0a:
              if (verbose >= 2) printf("[+] OPTION: Timezone... (%u bytes)\n", oh.option_length);
              break;
            /* Filter expression used */
            case 0x0b:
              if (verbose >= 2) printf("[+] OPTION: Filter expression... (%u bytes)\n",  oh.option_length);
              break;
            /* Operating System */
            case 0x0c:
              if (verbose >= 2) printf("[+] OPTION: Operating System... (%u bytes)\n",  oh.option_length);
              break;
            /* Frame Check Sequence Length */
            case 0x0d:
              if (verbose >= 2) printf("[+] OPTION: Frame Check Sequence Length... (%u bytes)\n",  oh.option_length);
              break;
            /* Timestamp Offset */
            case 0x0e:
              if (verbose >= 2) printf("[+] OPTION: Timestamp Offset... (%u bytes)\n",  oh.option_length);
              break;
          }

          /* Invalid Option? */
          if (oh.option_code > 0x0e) {
            printf("[-] Unknown option code: 0x%04x (%u bytes) ==> SKIPPING.\n", oh.option_code, oh.option_length);

            fixes++;

            if (count == 0) {
              printf("[*] No Options inside -> no need for End of Options...\n");
              break;
            }

            printf("[*] %u Options inside -> Finishing with End of Options...\n", count);

            oh.option_code = 0x00;
            oh.option_length = 0x00;
          }

          /* option is valid */

          /* copy options header into repaired block */
          memcpy(new_block+block_pos, &oh, sizeof(oh));
          block_pos += sizeof(oh);

          /* end of options? -> do not write any further*/
          if (oh.option_code == 0x00 && oh.option_length == 0x00) break;

          /* calculate padding for current option value */
          padding = oh.option_length;
          if (oh.option_length%4 != 0) padding += (4-oh.option_length%4);

          /* read option data */
          data = malloc(padding);
          bytes = fread(data, padding, 1, pcap);
          left -= padding;

          /* write option data into repaired block */
          memcpy(new_block+block_pos, data, padding);
          block_pos += padding;

          /* clean up memory */
          free(data);

          count++;
        }
        break;

      /* Name Resolution Block */
      case TYPE_NRB:

        if (shb_num == 0) {
          printf("[-] No Section Block header found ==> CREATING.\n");
          write_shb(pcap_fix);
          shb_num++;
          fixes++;
        }

        if (verbose) printf("[*] FOUND: Name Resolution Block: 0x%08x (%u bytes)\n", bh.block_type, bh.total_length);

        /* process records */
        count = 0;
        while (left > 0) {

          /* read name resolution block */
          bytes = fread(&nrb, sizeof(nrb), 1, pcap);	/* read first bytes of input file into struct */
          if (bytes != 1) return -3;
          left -= sizeof(nrb);

          /* which type of record did we get? */
          switch (nrb.record_type) {
            /* End of Records */
            case 0x00:
              if (verbose >= 2) printf("[+] RECORD: End of Records... (%u bytes)\n", nrb.record_length);
              break;
            /* IPv4 Record */
            case 0x01:
              if (verbose >= 2) printf("[+] RECORD: IPv4 Record... (%u bytes)\n", nrb.record_length);
              break;
            /* IPv6 Record */
            case 0x02:
              if (verbose >= 2) printf("[+] RECORD: IPv6 Record... (%u bytes)\n", nrb.record_length);
              break;
          }

          /* Invalid Record? */
          if (nrb.record_type > 0x02) {
            printf("[-] Unknown record type: 0x%04x (%u bytes) ==> SKIPPING.\n", nrb.record_type, nrb.record_length);

            fixes++;

            if (count == 0) {
              if (verbose) printf("[*] No Records inside -> no need for End of Records...\n");
              break;
            }

            if (verbose) printf("[*] %u Records inside -> Finishing with End of Records...\n", count);

            oh.option_code = 0x00;
            oh.option_length = 0x00;
          }

          /* record is valid */

          /* write name resolution block into repaired block */
          memcpy(new_block+block_pos, &nrb, sizeof(nrb));
          block_pos += sizeof(nrb);

          /* end of records? -> do not write any further */
          if (nrb.record_type == 0x00 && nrb.record_length == 0x00) break;

          /* calculate padding for current record value */
          padding = nrb.record_length;
          if (nrb.record_length % 4 != 0) padding += (4 - nrb.record_length % 4);

          /* read record value from input file */
          data = malloc(padding);
          bytes = fread(data, padding, 1, pcap);
          left -= padding;

          /* copy record value into repaired buffer */
          memcpy(new_block+block_pos, data, padding);
          block_pos += padding;

          /* clean up memory */
          free(data);

          count++;

        }

        /* options */
        count = 0;
        while (left > 0) {

          /* read options header */
          bytes = fread(&oh, sizeof(oh), 1, pcap);
          if (bytes != 1) return -3;
          left -= sizeof(oh);

          /* which option did we get? */
          switch (oh.option_code) {
            /* End of Options */
            case 0x00:
              if (verbose >= 2) printf("[+] OPTION: End of Options... (%u bytes)\n", oh.option_length);
              break;
            /* Comment Option */
            case 0x01:
              if (verbose >= 2) printf("[+] OPTION: Comment... (%u bytes)\n", oh.option_length);
              break;
            /* DNS Server Name */
            case 0x02:
              if (verbose >= 2) printf("[+] OPTION: DNS Server... (%u bytes)\n", oh.option_length);
              break;
            /* DNS Server IPv4 Address */
            case 0x03:
              if (verbose >= 2) printf("[+] OPTION: IPv4 Address of DNS Server... (%u bytes)\n", oh.option_length);
              break;
            /* DNS Server IPv6 Address */
            case 0x04:
              if (verbose >= 2) printf("[+] OPTION: IPv6 Address of DNS Server... (%u bytes)\n", oh.option_length);
              break;
          }

          /* Invalid Option? */
          if (oh.option_code > 0x04) {
            printf("[-] Unknown option code: 0x%04x (%u bytes) ==> SKIPPING.\n", oh.option_code, oh.option_length);

            fixes++;

            if (count == 0) {
              if (verbose) printf("[*] No Options inside -> no need for End of Options...\n");
              break;
            }

            if (verbose) printf("[*] %u Options inside -> Finishing with End of Options...\n", count);

            oh.option_code = 0x00;
            oh.option_length = 0x00;
          }

          /* option is valid */

          /* copy option header into repaired block */
          memcpy(new_block+block_pos, &oh, sizeof(oh));
          block_pos += sizeof(oh);

          /* end of options? -> do not write any further */
          if (oh.option_code == 0x00 && oh.option_length == 0x00) break;

          /* calculate padding for current option value */
          padding = oh.option_length;
          if (oh.option_length%4 != 0) padding += (4-oh.option_length%4);

          /* read option value from input file */
          data = malloc(padding);
          bytes = fread(data, padding, 1, pcap);
          left -= padding;

          /* copy option value into repaired block */
          memcpy(new_block+block_pos, data, padding);
          block_pos += padding;

          /* clean up memory */
          free(data);

          count++;

        }
        break;

      /* Interface Statistics Block */
      case TYPE_ISB:

        if (shb_num == 0) {
          printf("[-] No Section Block header found ==> CREATING.\n");
          write_shb(pcap_fix);
          shb_num++;
          fixes++;
        }

        if (verbose) printf("[*] FOUND: Interface Statistics Block: 0x%08x (%u bytes)\n", bh.block_type, bh.total_length);

        /* read interface statistics block */
        bytes = fread(&isb, sizeof(isb), 1, pcap);
        if (bytes != 1) return -3;
        left -= sizeof(isb);

        /* copy interface statistics block into repaired block */
        memcpy(new_block+block_pos, &isb, sizeof(isb));
        block_pos += sizeof(isb);

        /* options */
        count = 0;
        while (left > 0) {

          /* read options header */
          bytes = fread(&oh, sizeof(oh), 1, pcap);
          if (bytes != 1) return -3;
          left -= sizeof(oh);

          /* which option did we get? */
          switch (oh.option_code) {
            /* End of Options */
            case 0x00:
              if (verbose >= 2) printf("[+] OPTION: End of Options... (%u bytes)\n", oh.option_length);
              break;
            /* Comment Option */
            case 0x01:
              if (verbose >= 2) printf("[+] OPTION: Comment... (%u bytes)\n", oh.option_length);
              break;
            /* Capture Start Time */
            case 0x02:
              if (verbose >= 2) printf("[+] OPTION: Capture Start Time... (%u bytes)\n", oh.option_length);
              break;
            /* Capture End Time */
            case 0x03:
              if (verbose >= 2) printf("[+] OPTION: Capture End Time... (%u bytes)\n", oh.option_length);
              break;
            /* Packets recieved */
            case 0x04:
              if (verbose >= 2) printf("[+] OPTION: Packets recieved... (%u bytes)\n", oh.option_length);
              break;
            /* Packets dropped */
            case 0x05:
              if (verbose >= 2) printf("[+] OPTION: Packets dropped... (%u bytes)\n", oh.option_length);
              break;
            /* Packets accepted by Filter */
            case 0x06:
              if (verbose >= 2) printf("[+] OPTION: Filter packets accepted... (%u bytes)\n", oh.option_length);
              break;
            /* Packets dropped by Operating System */
            case 0x07:
              if (verbose >= 2) printf("[+] OPTION: Packets dropped by OS... (%u bytes)\n", oh.option_length);
              break;
            /* Packets delivered to user */
            case 0x08:
              if (verbose >= 2) printf("[+] OPTION: Packets delivered to user... (%u bytes)\n", oh.option_length);
              break;
          }

          /* Invalid Option? */
          if (oh.option_code > 0x08) {
            printf("[-] Unknown option code: 0x%04x (%u bytes) ==> SKIPPING.\n", oh.option_code, oh.option_length);

            fixes++;

            if (count == 0) {
              if (verbose) printf("[*] No Options inside -> no need for End of Options...\n");
              break;
            }

            if (verbose) printf("[*] %u Options inside -> Finishing with End of Options...\n", count);

            oh.option_code = 0x00;
            oh.option_length = 0x00;
          }

          /* option is valid */

          /* copy options header into repaired block */
          memcpy(new_block+block_pos, &oh, sizeof(oh));
          block_pos += sizeof(oh);

          /* end of options? -> do not write any further */
          if (oh.option_code == 0x00 && oh.option_length == 0x00) break;

          /* calculate padding for current option value */
          padding = oh.option_length;
          if (oh.option_length%4 != 0) padding += (4-oh.option_length%4);

          /* read option value from input file */
          data = malloc(padding);
          bytes = fread(data, padding, 1, pcap);
          left -= padding;

          /* copy option value into repaired block */
          memcpy(new_block+block_pos, data, padding);
          block_pos += padding;

          /* clean up memory */
          free(data);

          count++;
        }
        break;

      /* Enhanced Packet Block */
      case TYPE_EPB:

        if (shb_num == 0) {
          printf("[-] No Section Block header found ==> CREATING.\n");
          write_shb(pcap_fix);
          shb_num++;
          fixes++;
        }

        if (verbose >= 2) printf("[*] FOUND: Enhanced Packet Block: 0x%08x (%u bytes)\n", bh.block_type, bh.total_length);

        /* read enhanced packet block */
        bytes = fread(&epb, sizeof(epb), 1, pcap);
        if (bytes != 1) return -3;
        left -= sizeof(epb);

        while (epb.interface_id >= idb_num) {
          printf("[-] Missing IDB for Interface #%u ==> CREATING (#%u).\n", pb.interface_id, idb_num);
          write_idb(pcap_fix);
          idb_num++;
          fixes++;
        }

        /* copy enhanced packet block into repaired buffer */
        memcpy(new_block+block_pos, &epb, sizeof(epb));
        block_pos += sizeof(epb);

        /* calculate padding for packet data */
        padding = epb.caplen;
        if (epb.caplen % 4 != 0) padding += (4 - epb.caplen % 4);

        /* read packet data from input file */
        data = malloc(padding);
        bytes = fread(data, padding, 1, pcap);
        left -= padding;

        /* copy packet data into repaired block */
        memcpy(new_block+block_pos, data, padding);
        block_pos += padding;

        /* clean up memory */
        free(data);

        /* options */
        count = 0;
        while (left > 0) {

          /* read option header */
          bytes = fread(&oh, sizeof(oh), 1, pcap);
          if (bytes != 1) return -3;
          left -= sizeof(oh);

          /* which option did we get? */
          switch (oh.option_code) {
            /* End of Options */
            case 0x00:
              if (verbose >= 2) printf("[+] OPTION: End of Options... (%u bytes)\n", oh.option_length);
              break;
            /* Comment Option */
            case 0x01:
              if (verbose >= 2) printf("[+] OPTION: Comment... (%u bytes)\n", oh.option_length);
              break;
            /* Link Layer Flags */
            case 0x02:
              if (verbose >= 2) printf("[+] OPTION: Link Layer Flags... (%u bytes)\n", oh.option_length);
              break;
            /* Packet Hash */
            case 0x03:
              if (verbose >= 2) printf("[+] OPTION: Packet Hash... (%u bytes)\n", oh.option_length);
              break;
            /* Dropped Packets */
            case 0x04:
              if (verbose >= 2) printf("[+] OPTION: Dropped Packets Counter... (%u bytes)\n", oh.option_length);
              break;
          }

          /* Invalid Option? */
          if (oh.option_code > 0x04) {
            printf("[-] Unknown option code: 0x%04x (%u bytes) ==> SKIPPING.\n", oh.option_code, oh.option_length);

            fixes++;

            if (count == 0) {
              if (verbose) printf("[*] No Options inside -> no need for End of Options...\n");
              break;
            }

            if (verbose) printf("[*] %u Options inside -> Finishing with End of Options...\n", count);

            oh.option_code = 0x00;
            oh.option_length = 0x00;
          }

          /* option is valid */

          /* copy option header into repaired block */
          memcpy(new_block+block_pos, &oh, sizeof(oh));
          block_pos += sizeof(oh);

          /* end of options? -> do not write any further */
          if (oh.option_code == 0x00 && oh.option_length == 0x00) break;

          /* calculate padding for current option value */
          padding = oh.option_length;
          if (oh.option_length%4 != 0) padding += (4-oh.option_length%4);

          /* read option value from input file */
          data = malloc(padding);
          bytes = fread(data, padding, 1, pcap);
          left -= padding;

          /* copy option value into repaired block */
          memcpy(new_block+block_pos, data, padding);
          block_pos += padding;

          /* clean up memory */
          free(data);

          count++;
        }
        break;

    } /* end of switch - block header */

    /* check for invalid block header type */
    if (bh.block_type != TYPE_SHB && bh.block_type > TYPE_EPB) {
      printf("[-] Unknown block type!: 0x%08x ==> SKIPPING.\n", bh.block_type);

      fixes++;

    } else {
      /* write sizes of block header to correct positions */
      block_pos += sizeof(bh.total_length);
      memcpy(new_block+4, &block_pos, sizeof(bh.total_length));
      memcpy(new_block+block_pos-4, &block_pos, sizeof(bh.total_length));

      if (block_pos != bh.total_length) {
        if (verbose) printf("[*] Block size adjusted (%u --> %u).\n", bh.total_length, block_pos);
        fixes++;
      }

      /* write repaired block into output file */
      if (verbose >= 2) printf("[*] Writing block to file (%u bytes).\n", block_pos);
      fwrite(new_block, block_pos, 1, pcap_fix);
      free(new_block);

      if (bh.block_type == TYPE_SHB) shb_num++;
      if (bh.block_type == TYPE_IDB) idb_num++;
    }

    /* did we process all bytes of the block - given by block length */
    if (left == 0) {
      if (verbose >= 2) printf("[+] End of Block reached... byte counter is correct!\n");
    } else {
      /* we did not read until end of block - maybe due to option skipping */
      if (verbose) printf("[-] Did not hit the end of the block! (%ld bytes left)\n", left);
    }

    /* check for correct block end (block size) */
    bytes = fread(&check, sizeof(check), 1, pcap);

    /* block header sizes do not match! */
    if (check == bh.total_length) {
      if (verbose >= 2) printf("[+] Block size matches (%u)!\n", check);
    } else {
      bytes = ftell(pcap);
      printf("[-] Block size mismatch (%u != %u) ==> CORRECTED.\n", check, bh.total_length);

      /* we did not hit the end of block - need to search for next one */

      /* search for next valid block */
      if (verbose) printf("[*] Trying to align next block...\n");
      res = find_valid_block(pcap, filesize);
      printf("[-] Found %ld bytes of unknown data ==> SKIPPING.\n", ftell(pcap)-bytes);

      fixes++;

      if (res != 0) {
        if (verbose) printf("[*] No more valid blocks found inside file! (maybe it was the last one)\n");
        break;
      }

    }

    /* set positon of next block */
    pos = ftell(pcap);

  }

  /* everything successfull - return number of fixes */
  return(fixes);
}

int find_valid_block(FILE *pcap, unsigned long filesize) {
  unsigned int bytes;
  unsigned long i;
  unsigned int check;                       /* variable to check end of blocks sizes */
  struct block_header bh;

  /* bytewise processing of input file */
  for (i=ftell(pcap)-4; i<filesize; i++) {
    fseek(pcap, i, SEEK_SET);

    /* read possbile block header */
    bytes = fread(&bh, sizeof(bh), 1, pcap);
    if (bytes != 1) return(-1);

    /* check if:
     * - block header is greater than minimal size (12)
     * - block header type has a valid ID */
    if (bh.total_length >= 12 && bh.block_type >= TYPE_IDB && bh.block_type <= TYPE_EPB) {
      /* block header might be valid */

      /* check if the second size value is valid too */
      fseek(pcap, i+bh.total_length-4, SEEK_SET);
      bytes = fread(&check, sizeof(check), 1, pcap);
      if (check == bh.total_length) {
        /* also the second block size value is correct! */
        if (verbose) printf("[+] FOUND: Block (Type: 0x%08x) at Position %ld\n", bh.block_type, i);

        /* set pointer to next block position */
        fseek(pcap, i, SEEK_SET);
        return(0);
      }
    }
  }

  return(-1);
}

int write_shb(FILE *pcap_fix) {
  struct block_header bh;
  struct section_header_block shb;
  struct option_header oh;

  unsigned int size;
  unsigned int padding;
  unsigned char *data;

  char comment[] = "Added by pcapfix.\x00\x00\x00\x00";

  bh.block_type = TYPE_SHB;

  size = sizeof(struct block_header);

  shb.byte_order_magic = BYTE_ORDER_MAGIC;
  shb.major_version = 1;
  shb.minor_version = 0;

  size += sizeof(struct section_header_block);

  oh.option_code = 0x01; /* comment */
  oh.option_length = strlen(comment);

  size += sizeof(struct option_header);

  padding = oh.option_length;
  if (oh.option_length % 4 != 0) padding += (4 - oh.option_length % 4);

  size += padding;

  size += 4;  /* end of options */

  size += 4;  /* second block_length field */

  bh.total_length = size;

  data = malloc(size);
  memcpy(data, &bh, sizeof(bh));
  memcpy(data+sizeof(bh), &shb, sizeof(shb));
  memcpy(data+sizeof(bh)+sizeof(shb), &oh, sizeof(oh));
  memcpy(data+sizeof(bh)+sizeof(shb)+sizeof(oh), comment, padding);
  memset(data+sizeof(bh)+sizeof(shb)+sizeof(oh)+padding, 0, 4);
  memcpy(data+sizeof(bh)+sizeof(shb)+sizeof(oh)+padding+4, &size, sizeof(size));

  fwrite(data, size, 1, pcap_fix);

  return(0);
}

int write_idb(FILE *pcap_fix) {
  struct block_header bh;
  struct interface_description_block idb;
  struct option_header oh;

  unsigned int size;
  unsigned int padding;
  unsigned char *data;

  char comment[] = "Added by pcapfix.\x00\x00\x00\x00";

  bh.block_type = TYPE_IDB;

  size = sizeof(struct block_header);

  /* TODO: take from parameters */
  idb.linktype = 1;

  idb.reserved = 0;

  idb.snaplen = 65535;

  size += sizeof(struct interface_description_block);

  oh.option_code = 0x01; /* comment */
  oh.option_length = strlen(comment);

  size += sizeof(struct option_header);

  padding = oh.option_length;
  if (oh.option_length % 4 != 0) padding += (4 - oh.option_length % 4);

  size += padding;

  size += 4;  /* end of options */

  size += 4;  /* second block_length field */

  bh.total_length = size;

  data = malloc(size);
  memcpy(data, &bh, sizeof(bh));
  memcpy(data+sizeof(bh), &idb, sizeof(idb));
  memcpy(data+sizeof(bh)+sizeof(idb), &oh, sizeof(oh));
  memcpy(data+sizeof(bh)+sizeof(idb)+sizeof(oh), comment, padding);
  memset(data+sizeof(bh)+sizeof(idb)+sizeof(oh)+padding, 0, 4);
  memcpy(data+sizeof(bh)+sizeof(idb)+sizeof(oh)+padding+4, &size, sizeof(size));

  fwrite(data, size, 1, pcap_fix);

  return(0);
}