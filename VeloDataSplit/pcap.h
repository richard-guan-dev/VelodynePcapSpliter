#pragma once

namespace hadmap {
/* pacp�ļ����ɣ�

1�� pacp = pcap_head + pkt_head + pket_data +  next->pkt_head  +  next->pkt_data :  ����
2:  pkt_data=frame_head + ip_head + tcp_head +tcp_data

//���� pacp_head �е� linktype �־����� frame_head ������


*/
typedef unsigned int  u_int32;
typedef unsigned short  u_int16;
typedef unsigned char u_int8;
typedef int int32;
/*
Pcap�ļ�ͷ24B���ֶ�˵����
Magic��4B��0xa1b2c3d4:������ʾ�ļ��Ŀ�ʼ
Major��2B��0x02 00:��ǰ�ļ���Ҫ�İ汾��
Minor��2B��0x04 00��ǰ�ļ���Ҫ�İ汾��
ThisZone��4B���صı�׼ʱ�䣻ȫ��
SigFigs��4Bʱ����ľ��ȣ�ȫ��
SnapLen��4B���Ĵ洢����
LinkType��4B��·����
�������ͣ�
��0            BSD loopback devices, except for later OpenBSD
 1            Ethernet, and Linux loopback devices
 6            802.5 Token Ring
 7            ARCnet
 8            SLIP
 9            PPP
 */
typedef struct PcapHeader {
    u_int32 magic;
    u_int16 version_major;
    u_int16 version_minor;
    int32 thiszone;
    u_int32 sigfigs;
    u_int32 snaplen;
    u_int32 linktype;
} PcapHeader;

/*
Packet ��ͷ��Packet�������
�ֶ�˵����
Timestamp��ʱ�����λ����ȷ��seconds
Timestamp��ʱ�����λ����ȷ��microseconds
Caplen����ǰ�������ĳ��ȣ���ץȡ��������֡���ȣ��ɴ˿��Եõ���һ������֡��λ�á�
Len���������ݳ��ȣ�������ʵ������֡�ĳ��ȣ�һ�㲻����caplen����������º�Caplen��ֵ��ȡ�
Packet ���ݣ��� Packet��ͨ��������·�������֡���������ݣ����Ⱦ���Caplen��������ȵĺ��棬
���ǵ�ǰPCAP�ļ��д�ŵ���һ��Packet���ݰ���Ҳ�� ��˵��PCAP�ļ����沢û�й涨�����Packet���ݰ�֮����ʲô����ַ�����
��һ���������ļ��е���ʼλ�á�������Ҫ����һ��Packet��ȷ����
*/

typedef struct  Timestamp {
    u_int32 timestamp_s;
    u_int32 timestamp_ms;
} Timestamp;

typedef struct PktHeader {
    Timestamp ts;
    u_int32 capture_len;
    u_int32 len;

} PktHeader;


typedef struct Ethernet {
    u_int8  dst_mac[6];   //Ŀ��MAC��ַ
    u_int8  src_mac[6];   //ԴMAC��ַ
    u_int16 frame_type;    //֡����
} Ethernet;


typedef struct LinuxCookedCapture {
    u_int16 package_type;
    u_int16 address_type;
    u_int16 address_length;
    u_int16 un_used[4];
    u_int16 frame_type; //֡����
} LinuxCookedCapture;


typedef struct IpHeader {
    //IP���ݱ�ͷ
    u_int8   ver_hlen;       //�汾+��ͷ����
    u_int8   tos;            //��������
    u_int16  totla_length;       //�ܳ���
    u_int16  id;     //��ʶ
    u_int16  flag_segment;   //��־+Ƭƫ��
    u_int8   ttl;            //��������
    u_int8   protocol;       //Э������
    u_int16  checksum;       //ͷ��У���
    u_int32  src_ip;  //ԴIP��ַ
    u_int32  dst_ip;  //Ŀ��IP��ַ
} IpHeader;


typedef struct TcpHeader {
    //TCP���ݱ�ͷ
    u_int16  src_port;    //Դ�˿�
    u_int16  dst_port;    //Ŀ�Ķ˿�
    u_int32  seq_no;  //���
    u_int32  ack_no;  //ȷ�Ϻ�
    u_int8   header_len;  //���ݱ�ͷ�ĳ���(4 bit) + ����(4 bit)
    u_int8   flags;  //��ʶTCP��ͬ�Ŀ�����Ϣ
    u_int16  window;     //���ڴ�С
    u_int16  checksum;   //У���
    u_int16  urgent_pointer;  //����ָ��
} TcpHeader;

typedef struct UdpHeader {
    //����UDP�ײ�
    u_int16    src_port;        //16λԴ�˿�
    u_int16    dst_port;        //16λĿ�Ķ˿�
    u_int16    length;         //16λ����
    u_int16    checksum;         //16λУ���
} UdpHeader;
}