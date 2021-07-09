/* interfaz 2*/
import com.sun.jna.Platform;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapHandle.TimestampPrecision;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.PcapStat;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.NifSelector;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import sun.jvmstat.perfdata.monitor.protocol.local.PerfDataFile;

@SuppressWarnings("javadoc")
public class GetNextRawPacket {

    private static final String COUNT_KEY = GetNextRawPacket.class.getName() + ".count";
    public static int COUNT = Integer.getInteger(COUNT_KEY, 15);  //<<<<--------------------------------------Cuantas tramas quiero capturar (contador)

    private static final String READ_TIMEOUT_KEY = GetNextRawPacket.class.getName() + ".readTimeout";
    private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

    private static final String SNAPLEN_KEY = GetNextRawPacket.class.getName() + ".snaplen";
    private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

    private static final String BUFFER_SIZE_KEY = GetNextRawPacket.class.getName() + ".bufferSize";
    private static final int BUFFER_SIZE
            = Integer.getInteger(BUFFER_SIZE_KEY, 1 * 1024 * 1024); // [bytes]

    private static final String NIF_NAME_KEY = GetNextRawPacket.class.getName() + ".nifName";
    private static final String NIF_NAME = System.getProperty(NIF_NAME_KEY);

    private GetNextRawPacket() {
    }

    private static int numETHERNET = 0, numIEEE = 0, numARP = 0, numIP = 0, numICMP = 0, numIGMP = 0, numTCP = 0, numUDP = 0;

    //-------------------------------------------------------------------LEER ARCHIVO------------------------------
    private static final int COUNT2 = 32;

    private static final String PCAP_FILE_KEY = GetNextRawPacket.class.getName() + ".pcapFile";

    //System.getProperty(PCAP_FILE_KEY, "src/main/resources/echoAndEchoReply.pcap");
    //-------------------------------------------------------------------------------------------------------------
    public static void main(String[] args) throws PcapNativeException, NotOpenException {
        ///*     ----> Colocar la interfaz'
        // new Interfaz().setVisible(true);
        //*/
        PcapDumper dumper = null;
        String filter = args.length != 0 ? args[0] : "";

        //System.out.println(COUNT_KEY + ": " + COUNT);
        System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
        System.out.println(SNAPLEN_KEY + ": " + SNAPLEN);
        System.out.println(BUFFER_SIZE_KEY + ": " + BUFFER_SIZE);
        System.out.println(NIF_NAME_KEY + ": " + NIF_NAME);
        System.out.println("\n");

        PcapNetworkInterface nif;

        if (NIF_NAME != null) {
            nif = Pcaps.getDevByName(NIF_NAME);
        } else {
            try {
                nif = new NifSelector().selectNetworkInterface();
            } catch (IOException e) {
                e.printStackTrace();
                return;
            }

            if (nif == null) {
                return;
            }
        }

        System.out.println(nif.getName() + " (" + nif.getDescription() + ")");
        for (PcapAddress addr : nif.getAddresses()) {
            if (addr.getAddress() != null) {
                System.out.println("IP address: " + addr.getAddress());
            }
        }
        System.out.println("");
        
        System.out.println("------------------------------------------------------------------------------------------------------------------------------");
        System.out.println("|                                                                                                                            |");
        System.out.println("|                                              Analizador de Protocolos                                                      |");
        System.out.println("|                                                                                                                            |");
        System.out.println("------------------------------------------------------------------------------------------------------------------------------");
        System.out.println("\n");

        System.out.println("-------------------<<<<<<<<< 1.- Seleccionar un archivo '.pcap'  2.- Obtener tramas al instante >>>>>>>>>>-------------------");
        Scanner scanArchivo = new Scanner(System.in);
        int abrirArchivo = scanArchivo.nextInt();
        PcapHandle handle;
        if (abrirArchivo == 1) {                //Abre un archivo 
            System.out.println("Escriba el nombre del archivo a analizar: ");
            Scanner teclearArchivo = new Scanner(System.in);
            String archivoPCAP;
            archivoPCAP = teclearArchivo.nextLine();

            String PCAP_FILE = System.getProperty(PCAP_FILE_KEY, archivoPCAP);
            try {
                handle = Pcaps.openOffline(PCAP_FILE, TimestampPrecision.NANO);
            } catch (PcapNativeException e) {
                handle = Pcaps.openOffline(PCAP_FILE);
            }

        } else {                                    //Escanea tramas al instante
            handle
                    = new PcapHandle.Builder(nif.getName())
                            .snaplen(SNAPLEN)
                            .promiscuousMode(PromiscuousMode.PROMISCUOUS)
                            .timeoutMillis(READ_TIMEOUT)
                            .bufferSize(BUFFER_SIZE)
                            .build();
        }

        Scanner seleccion = new Scanner(System.in);
        Scanner tipoFiltro = new Scanner(System.in);
        Scanner scanTemporal = new Scanner(System.in);
        Scanner scanTempora2 = new Scanner(System.in);
        Scanner teclearDirecciones = new Scanner(System.in);
        String temporalFilter = "";
        int opcionFiltro;
        int opcionFinal;
        String opcionFinal2;
        System.out.println("-------------------<<<<<<<<<  Quieres un filtro para la captura de tramas? >>>>>>>>>>-------------------");
        System.out.println("1.- Si \t\t 2.-No");
        int respuestaFiltro = seleccion.nextInt();

        if (respuestaFiltro == 1) {
            System.out.println("----------->Selecciona un tipo de filtro <-----------");
            System.out.println(" 1.- Tipo de protocolo \n 2.- Por Host \n 3.- Por puerto \n 4.- Por tamaño \n 5.- Cantidad de Tramas a capturar");
            opcionFiltro = tipoFiltro.nextInt();
            switch (opcionFiltro) {
                case 1:
                    System.out.println("  1.-ARP \n  2.-IP \n  3.-ICMP \n  4.-IGMP \n  5.-TCP \n  6.-UDP");
                    opcionFinal = scanTemporal.nextInt();
                    switch (opcionFinal) {
                        case 1:
                            temporalFilter = "arp";
                            break;
                        case 2:
                            temporalFilter = "ip";
                            break;
                        case 3:
                            temporalFilter = "icmp";
                            break;
                        case 4:
                            temporalFilter = "igmp";
                            break;
                        case 5:
                            temporalFilter = "tcp";
                            break;
                        case 6:
                            temporalFilter = "udp";
                            break;
                    }
                    break;

                case 2:
                    System.out.println("  1.-Origen \n  2.-Destino");
                    opcionFinal = scanTemporal.nextInt();
                    if (opcionFinal == 1) {
                        System.out.println("Digite la direccion ip origen: ");
                        opcionFinal2 = teclearDirecciones.nextLine();
                        temporalFilter = "src host " + opcionFinal2;
                    } else {
                        System.out.println("Digite la direccion ip destino: ");
                        opcionFinal2 = teclearDirecciones.nextLine();
                        temporalFilter = "dst host " + opcionFinal2;
                    }
                    break;

                case 3:
                    System.out.println("  Coloque el numero de puerto a capturar");
                    opcionFinal = scanTemporal.nextInt();
                    temporalFilter = "port " + opcionFinal;
                    break;

                case 4:
                    System.out.println("  1.-Menor o igual que (<=) \n  2.-Mayor o igual que (>=)");
                    opcionFinal = scanTemporal.nextInt();
                    if (opcionFinal == 1) {
                        System.out.println("Digite el tamaño del paquete que sea <=");
                        opcionFinal2 = teclearDirecciones.nextLine();
                        temporalFilter = "less " + opcionFinal2;
                    } else {
                        System.out.println("Digite el tamaño del paquete que sea >=");
                        opcionFinal2 = teclearDirecciones.nextLine();
                        temporalFilter = "greater " + opcionFinal2;
                    }
                    break;

                case 5:
                    System.out.println("  Coloque el numero de tramas que quiere capturar");
                    opcionFinal = scanTemporal.nextInt();
                    int numTramas = (opcionFinal != 0) ? opcionFinal : 5;
                    COUNT = Integer.getInteger(COUNT_KEY, numTramas);  //<<<<--------------------------------------Cuantas tramas quiero capturar (contador)
                    break;
            }
            filter = temporalFilter;
        }

        handle.setFilter(filter, BpfCompileMode.OPTIMIZE);

        if (dumper == null) {
            dumper = handle.dumpOpen("archivo.pcap");                       // Si es nulo se crea el archivo .pcap y se abre
        }

        int num = 0;
        while (true) {
            byte[] packet = handle.getNextRawPacket();
            if (packet == null) {
                continue;
            } else {
                dumper.dumpRaw(packet);                                     //Se le pasa la trama en crudo para grabarla
                System.out.println("\n\n\t\t--->EL NUMERO DE TRAMA CAPTURADA ES: " + (num + 1));
                System.out.println(handle.getTimestamp());
                System.out.println(ByteArrays.toHexString(packet, " "));
                for (int j = 0; j < packet.length; j++) {
                    System.out.printf("%02X ", packet[j]);
                    // System.out.println("Posicion: --> " + j);
                    if (j % 16 == 0) {
                        System.out.println("");
                    }
                }//for
                System.out.println("");
                num++;

                System.out.println("");
                obtenerMAC(packet);
                /**
                 * ******************************************************************************************************************
                 */
                int tipo_b1 = (packet[12] >= 0) ? packet[12] * 256 : (packet[12] + 256) * 256;
                int tipo_b2 = (packet[13] >= 0) ? packet[13] : packet[13] + 256;
                int tipo = tipo_b1 + tipo_b2;
                //System.out.println("\nTipo" + tipo);

                switch (tipo) {

                    case (int) 2054: {             //   ----------------------------->Encabezado ARP 
                        System.out.println("-------------> Tipo ARP <---------------");
                        hardwareType(packet);
                        protocolType(packet);
                        hardwareAdressLength(packet);
                        protocolAdressLength(packet);
                        opCode(packet);
                        senderAddres(packet);
                        targetAddres(packet);
                        numARP++;
                        break;
                    }

                    case (int) 2048: {            //   ----------------------------->Encabezado IP 

                        System.out.println("-------------> Tipo IP <---------------");
                        try {
                            //IP
                            numIP++;
                            int ihl = (packet[14] & 0x0f) * 4;
                            byte[] tmp_ip = Arrays.copyOfRange(packet, 14, 14 + ihl); // Creo una copia solo del encabezado IP, apartir del byte 14
                            IpV4Packet ip = IpV4Packet.newPacket(tmp_ip, 0, tmp_ip.length);
                            //Campo IHL
                            System.out.println("Tam paquete IP:" + ihl + " bytes");
                            //Campo Version
                            versionIP(ip);
                            //Campo IHL
                            ihlIP(ip);
                            //Campo Servicios Diferenciados                         
                            difServicesIP(ip);
                            //Campo Longitud total PDU
                            longTotalIP(ip);
                            //Campo Bit identificacion   
                            bitIdIP(ip);
                            //Campo Banderas
                            flagsIP(ip);
                            //Campo Offset
                            offsetIP(ip);
                            //Campo Tiempo de vida [TTL] 
                            lifeTimeIP(ip);
                            //Campo protocolo
                            protocolIP(ip);
                            //Campo Checksum
                            checksumIP(ip);
                            //Campo Direccion IP Origen
                            sourceIP(ip);
                            //Campo Direccion IP Destino 
                            destinIP(ip);
                            //Campo Opciones y dato
                            // List <IpV4Packet.IpV4Option>;

                            int proto = ip.getHeader().getProtocol().value().intValue();
                            switch (proto) {
                                case (int) 1:
                                    tipoICMP(packet, ihl, ip, proto, tmp_ip); //   ----------------------------->PROTOCOLO ICMP 
                                    break;
                                case (int) 2:
                                    tipoIGMP(packet, ihl, ip, proto, tmp_ip); //   ----------------------------->PROTOCOLO IGMP 
                                    break;
                                case (int) 6:
                                    tipoTCP(packet, ihl, ip, proto, tmp_ip);  //   ----------------------------->PROTOCOLO TCP
                                    break;
                                case (int) 17:
                                    tipoUDP(packet, ihl, ip, proto, tmp_ip);  //   ----------------------------->PROTOCOLO UDP 
                                    break;
                            }
                        } catch (IllegalRawDataException ex) {
                            Logger.getLogger(GetNextRawPacket.class.getName()).log(Level.SEVERE, null, ex);
                        }//catch
                        break;
                    }

                }
                /**
                 * ******************************************************************************************************************
                 */

                if (num >= COUNT) {
                    break;
                }
            }
        }
        System.out.println("\n\n");
        System.out.println("-------------------------------............----------------------------");
        System.out.println("------------------------------>ESTADISTICAS<---------------------------");
        System.out.println("-------------------------------............----------------------------");
        System.out.println("El numero de tramas ARP es: " + numIEEE + "\t Y su porcentaje es: " + estadisticaPorcentaje(numIEEE, COUNT) + "%");
        System.out.println("El numero de tramas ARP es: " + numARP + "\t Y su porcentaje es: " + estadisticaPorcentaje(numARP, COUNT) + "%");
        System.out.println("El numero de tramas IP es: " + numIP + "\t Y su porcentaje es: " + estadisticaPorcentaje(numIP, COUNT) + "%");
        System.out.println("El numero de tramas ICMP es: " + numICMP + "\t    Y su porcentaje es: " + estadisticaPorcentaje(numICMP, COUNT) + "%");
        System.out.println("El numero de tramas IGMP es: " + numIGMP + "\t    Y su porcentaje es: " + estadisticaPorcentaje(numIGMP, COUNT) + "%");
        System.out.println("El numero de tramas TCP es: " + numTCP + "\t    Y su porcentaje es: " + estadisticaPorcentaje(numTCP, COUNT) + "%");
        System.out.println("El numero de tramas UDP es: " + numUDP + "\t    Y su porcentaje es: " + estadisticaPorcentaje(numUDP, COUNT) + "%");
        System.out.println("--------------------------------------------------------------------");
        System.out.println("");
        dumper.close();                                                     //Se cierra el archivo .pcap 

        /*       Lo de abajo si funciona para capturar tramas al instante       */
//        PcapStat ps = handle.getStats();
//        System.out.println("ps_recv: " + ps.getNumPacketsReceived());
//        System.out.println("ps_drop: " + ps.getNumPacketsDropped());
//        System.out.println("ps_ifdrop: " + ps.getNumPacketsDroppedByIf());
//        if (Platform.isWindows()) {
//            System.out.println("bs_capt: " + ps.getNumPacketsCaptured());
//        }
        handle.close();

    }//main

    /*----------------------------------------------------------------------------------------------------Inicio de la Trama-----------------------------------------------------------------------*/
    public static void obtenerMAC(byte[] trama) {
        System.out.printf("MAC DESTINO:");
        for (int r = 0; r < 6; r++) {     //Obtener la direccion MAC Destino
            if (r % 16 == 0) {
                System.out.println("");
            }
            System.out.printf("%02X ", trama[r]);

        }
        System.out.println("");
        System.out.println("MAC ORIGEN:");
        for (int r = 6; r < 12; r++) {     //Obtener la direccion MAC Origen
            if (r % 16 == 0) {
                System.out.println("");
            }
            System.out.printf("%02X ", trama[r]);
        }
        System.out.println("");
    }

    /*----------------------------------------------------------------------------------------------------ESTADISTICAS-----------------------------------------------------------------------*/
    public static int estadisticaPorcentaje(int numProtocolo, int COUNT) {

        int porcentajeFinal = 0;
        porcentajeFinal = (numProtocolo * 100) / COUNT;
        return porcentajeFinal;
    }

    /*----------------------------------------------------------------------------------------------------TIPO IP-----------------------------------------------------------------------*/
 /*public static void ipTypeIP(byte[] trama) {
        //IP
        int ihl = (trama[14] & 0x0f) * 4;

    }*/
    public static void versionIP(IpV4Packet ip) {
        //Campo Version
        System.out.println("Version: " + ip.getHeader().getVersion().valueAsString());

    }

    public static void ihlIP(IpV4Packet ip) {
        //Campo IHL
        System.out.println("IHL: " + ip.getHeader().getIhlAsInt());

    }

    public static void difServicesIP(IpV4Packet ip) {
        //Campo Servicios Diferenciados                         
        System.out.println("Serv.Dif: " + ip.getHeader().getTos().toString());

    }

    public static void longTotalIP(IpV4Packet ip) {
        //Campo Longitud total PDU
        int longTotal = (ip.getHeader().getTotalLength() > 0) ? ip.getHeader().getTotalLength() : ip.getHeader().getTotalLength() + 65536;
        System.out.println("Longitud Total: " + longTotal);
        //System.out.println("Prueba TOTAL: " + ip.getHeader().getTotalLength());

    }

    public static void bitIdIP(IpV4Packet ip) {
        //Campo Bit identificacion  
        int id = (ip.getHeader().getIdentification() > 0) ? ip.getHeader().getIdentification() : ip.getHeader().getIdentification() + 65536;
        System.out.println("ID: " + id);

    }

    public static void flagsIP(IpV4Packet ip) {
        //Campo Banderas
        String df = (ip.getHeader().getDontFragmentFlag()) ? "Encendido" : "Apagado";
        String mf = (ip.getHeader().getMoreFragmentFlag()) ? "Encendido" : "Apagado";
        System.out.println("Banderas: \nNo fragmentar: " + df + "\nFaltan fragmentos: " + mf);
    }

    public static void offsetIP(IpV4Packet ip) {
        //Campo Offset
        int desplazamiento = (ip.getHeader().getFragmentOffset() > 0) ? ip.getHeader().getFragmentOffset() : ip.getHeader().getFragmentOffset() + 65536;
        System.out.println("Fregmento offset: " + desplazamiento);
    }

    public static void lifeTimeIP(IpV4Packet ip) {
        //Campo Tiempo de vida [TTL] 
        System.out.println("TTL: " + ip.getHeader().getTtlAsInt());
    }

    public static void protocolIP(IpV4Packet ip) {
        //Campo protocolo
        System.out.println("Protocolo:" + ip.getHeader().getProtocol().name());
    }

    public static void checksumIP(IpV4Packet ip) {
        //Campo Checksum
        System.out.printf("Checksum: %02X \n", ip.getHeader().getHeaderChecksum());
    }

    public static void sourceIP(IpV4Packet ip) {
        //Campo Direccion IP Origen
        System.out.println("IP origen: " + ip.getHeader().getSrcAddr().getHostAddress());
    }

    public static void destinIP(IpV4Packet ip) {
        //Campo Direccion IP Destino 
        System.out.println("IP destino: " + ip.getHeader().getDstAddr().getHostAddress());
    }

    /*----------------------------------------------------------------------------------------------------TIPO ICMP-----------------------------------------------------------------------*/
    public static void tipoICMP(byte[] trama, int ihl, IpV4Packet ip, int proto, byte[] tmp_ip) { //-------------------------------------------------------------->ICMP
        try {// 1

            System.out.println("---------->ICMP<----------");
            numICMP++;
            int longTotal = (ip.getHeader().getTotalLength() > 0) ? ip.getHeader().getTotalLength() : ip.getHeader().getTotalLength() + 65536;
            int lt_PDU_trans = longTotal - (ihl);
            byte[] tmp_icmp = Arrays.copyOfRange(trama, 14 + ihl, 14 + ihl + lt_PDU_trans);
            IcmpV4CommonPacket icmp = IcmpV4CommonPacket.newPacket(tmp_icmp, 0, tmp_icmp.length);
            System.out.println("Tipo: " + icmp.getHeader().getType().valueAsString() + "(" + icmp.getHeader().getType().name() + ")");
            System.out.println("Código: " + icmp.getHeader().getCode().valueAsString() + "(" + icmp.getHeader().getCode().name() + ")");
            //}

        } catch (IllegalRawDataException ex) {
            Logger.getLogger(GetNextRawPacket.class.getName()).log(Level.SEVERE, null, ex);
        }//catch
    }

    /*----------------------------------------------------------------------------------------------------TIPO IGMP-----------------------------------------------------------------------*/
    //---------------------------------------------------------------------------------
    public static byte getUDPByte(byte[] packet, int ihl, int tam) {
        byte udpbyte;
        udpbyte = Arrays.copyOfRange(packet, 14 + ihl + tam - 1, 14 + ihl + tam)[0];
        return udpbyte;
    } 
    //---------------------------------------------------------------------------------

    public static void tipoIGMP(byte[] trama, int ihl, IpV4Packet ip, int proto, byte[] tmp_ip) { //trama completa // 2

        System.out.println("---------->IGMP<----------");
        numIGMP++;
        int tam = 0;
        tam++;
        int version = getUDPByte(trama, ihl, tam);
        System.out.println("Decimal:  " + version);
        switch (version) {
            case 17:
                System.out.println("Tipo: Membership Query (0x11)");
                break;
            case 18:
                System.out.println("Tipo: IGMPv1 Membership Report (0x12)");
                tam++;
                System.out.println("Reservado: " + getUDPByte(trama, ihl, tam));
                tam++;
                System.out.println("Checksum: " + getUDPByte(trama, ihl, tam) + getUDPByte(trama, ihl, tam + 1));
                break;
            case 22:
                System.out.println("Tipo: IGMPv2 Membership Report (0x16)");
                tam++;
                float tiempo = getUDPByte(trama, ihl, tam);
                tiempo /= 10;
                System.out.println("Tiempo maximo de respuesta: %f sec " + tiempo + getUDPByte(trama, ihl, tam));
                tam++;
                System.out.println("Checksum: " + getUDPByte(trama, ihl, tam) + getUDPByte(trama, ihl, tam + 1));
                break;
            case 34:
                System.out.println("Tipo: IGMPv3 Membership Report (0x22)");
                tam++;
                System.out.println("Reservado: " + getUDPByte(trama, ihl, tam));
                tam++;
                System.out.println("Checksum: " + getUDPByte(trama, ihl, tam) + getUDPByte(trama, ihl, tam + 1));
                tam += 2;
                System.out.println("Reservado: " + getUDPByte(trama, ihl, tam) + getUDPByte(trama, ihl, tam + 1));
                tam += 2;
                int record = (getUDPByte(trama, ihl, tam) << 8) + getUDPByte(trama, ihl, tam + 1);
                System.out.println("Número de registros de grupo: " + record);
                break;
            case 23:
                System.out.println("Tipo: Leave Group (0x17)");
                break;
        }
//                int longTotal = (ip.getHeader().getTotalLength() > 0) ? ip.getHeader().getTotalLength() : ip.getHeader().getTotalLength() + 65536;
//                int lt_PDU_trans = longTotal - (ihl);
//                byte[] tmp_igmp = Arrays.copyOfRange(trama, 14 + ihl, 14 + ihl + lt_PDU_trans);
//                //IcmpV4CommonPacket icmp = IcmpV4CommonPacket.newPacket(tmp_icmp, 0, tmp_icmp.length);
//                System.out.println(tmp_igmp);
//            //System.out.println("Tipo: " + icmp.getHeader().getType().valueAsString() + "(" + icmp.getHeader().getType().name() + ")");
//            //System.out.println("Código: " + icmp.getHeader().getCode().valueAsString() + "(" + icmp.getHeader().getCode().name() + ")");

    }

    /*----------------------------------------------------------------------------------------------------TIPO TCP-----------------------------------------------------------------------*/
    public static void tipoTCP(byte[] trama, int ihl, IpV4Packet ip, int proto, byte[] tmp_ip) { //-------------------------------------------------------------->TCP
        try { //6

            System.out.println("---------->TCP<----------");
            numTCP++;
            int longTotal = (ip.getHeader().getTotalLength() > 0) ? ip.getHeader().getTotalLength() : ip.getHeader().getTotalLength() + 65536;
            int lt_PDU_trans = longTotal - (ihl);
            byte[] tmp_tcp = Arrays.copyOfRange(trama, 14 + ihl, 14 + ihl + lt_PDU_trans);
            TcpPacket tcp = TcpPacket.newPacket(tmp_tcp, 0, tmp_tcp.length);
            int pto_o = (tcp.getHeader().getSrcPort().valueAsInt() > 0) ? tcp.getHeader().getSrcPort().valueAsInt() : tcp.getHeader().getSrcPort().valueAsInt() + 65536;
            System.out.println("Puerto origen: " + pto_o);
            System.out.println("Puerto destino: " + tcp.getHeader().getDstPort());
            System.out.println("Numero de Sequence: " + tcp.getHeader().getSequenceNumberAsLong());
            System.out.println("Numero de Acknowledgment: " + tcp.getHeader().getAcknowledgmentNumberAsLong());
            System.out.println("Bandera FIN: " + tcp.getHeader().getFin());
            System.out.println("Bandera SYN: " + tcp.getHeader().getSyn());
            System.out.println("Bandera RST: " + tcp.getHeader().getRst());
            System.out.println("Bandera PSH: " + tcp.getHeader().getPsh());
            System.out.println("Bandera ACK: " + tcp.getHeader().getAck());
            System.out.println("Bandera URG: " + tcp.getHeader().getUrg());
            System.out.println("Tamaño de ventana: " + tcp.getHeader().getWindowAsInt());
            System.out.println("Checksum: " + tcp.getHeader().getChecksum());
            System.out.println("Apuntador urgente: " + tcp.getHeader().getUrgentPointerAsInt());

        } catch (IllegalRawDataException ex) {
            Logger.getLogger(GetNextRawPacket.class
                    .getName()).log(Level.SEVERE, null, ex);
        }//catch
    }

    /*----------------------------------------------------------------------------------------------------TIPO UDP-----------------------------------------------------------------------*/
    public static void tipoUDP(byte[] trama, int ihl, IpV4Packet ip, int proto, byte[] tmp_ip) { //-------------------------------------------------------------->UDP
        try {//17

            System.out.println("---------->UDP<----------");
            numUDP++;
            int longTotal = (ip.getHeader().getTotalLength() > 0) ? ip.getHeader().getTotalLength() : ip.getHeader().getTotalLength() + 65536;
            int lt_PDU_trans = longTotal - (ihl);
            int par2 = 14 + ihl;
            int par3 = 14 + ihl + lt_PDU_trans;
//            System.out.println("PAR 2:   "  + par2);
//            System.out.println("PAR 3:   "  + par3);
            byte[] tmp_udp = Arrays.copyOfRange(trama, par2, par3);
            UdpPacket udp = UdpPacket.newPacket(tmp_udp, 0, tmp_udp.length);
            int upto_o = (udp.getHeader().getSrcPort().valueAsInt() > 0) ? udp.getHeader().getSrcPort().valueAsInt() : udp.getHeader().getSrcPort().valueAsInt() + 65536;
            System.out.println("Puerto origen: " + upto_o);
            System.out.println("Puerto destino: " + udp.getHeader().getDstPort().valueAsString());
            System.out.println("Longitud UDP: " + udp.getHeader().getLengthAsInt());
            System.out.println("Checksum UDP: " + udp.getHeader().getChecksum());

        } catch (IllegalRawDataException ex) {
            Logger.getLogger(GetNextRawPacket.class
                    .getName()).log(Level.SEVERE, null, ex);
        }//catch
    }


    /*----------------------------------------------------------------------------------------------------TIPO ARP-----------------------------------------------------------------------*/
    public static void hardwareType(byte[] trama) {
        System.out.printf("Tipo de Hardware: ");
        for (int r = 14; r < 16; r++) {     //Obtener el tipo de hardware, en este caso tiene que ser 1 
            if (r % 16 == 0) {
                // System.out.println("");
            }
            System.out.printf("%02X ", trama[r]);

        }
        System.out.println("");
    }

    public static void protocolType(byte[] trama) {
        System.out.printf("Tipo de Protocolo: ");
        for (int r = 16; r < 18; r++) {     //Obtener el tipo de protocolo, en este caso tiene que ser 0x0800 
            if (r % 16 == 0) {
                // System.out.println("");
            }
            System.out.printf("%02X ", trama[r]);

        }
        System.out.println("");
    }

    public static void hardwareAdressLength(byte[] trama) {
        System.out.printf("Tamaño de la direccion fisica: ");
        for (int r = 18; r < 19; r++) {     //Obtener el tamaño de la direccion fisica, en este caso tiene que ser 0x06 
            if (r % 16 == 0) {
                // System.out.println("");
            }
            System.out.printf("%02X ", trama[r]);

        }
        System.out.println("");
    }

    public static void protocolAdressLength(byte[] trama) {
        System.out.printf("Tamaño del protocolo: ");
        for (int r = 19; r < 20; r++) {     //Obtener el tamaño de la direccion ip(protocolo IP), en este caso tiene que ser 0x04 
            if (r % 16 == 0) {
                System.out.println("");
            }
            System.out.printf("%02X ", trama[r]);

        }
        System.out.println("");
    }

    public static void opCode(byte[] trama) {
        System.out.printf("Codigo de operacion: ");
        for (int r = 20; r < 22; r++) {     //Obtener el tipo de peticion
            if (r % 16 == 0) {
                System.out.println("");
            }
            System.out.printf("%02X ", trama[r]);

        }
        System.out.printf(" -----> ");
        switch (trama[21]) {
            case 1:
                System.out.println("ARP Request (Solicitud a ARP)");
                break;
            case 2:
                System.out.println("ARP Reply (Respuesta a ARP)");
                break;
            case 3:
                System.out.println("RARP Request (Solicitud a ARP inverso)");
                break;
            case 4:
                System.out.println("RARP Reply (Respuesta a ARP inverso)");
                break;
            default:
                System.out.println("Valor no indentificado");
        }
    }

    public static void senderAddres(byte[] trama) {
        System.out.printf("Sender hardware address: ");
        for (int r = 22; r < 28; r++) {     //Obtener el "quien esta haciendo la pregunta, direccion MAC " 
            if (r % 16 == 0) {
                System.out.println("");
            }
            System.out.printf("%02X ", trama[r]);
        }
        System.out.println("");
        System.out.printf("Sender protocol address: ");
        for (int r = 28; r < 32; r++) {     //Obtener el "la direccion de quien esta preguntando , direccion IP"
            if (r % 16 == 0) {
                System.out.println("");
            }
            System.out.printf("%02X ", trama[r]);
        }
        System.out.println("");
    }

    public static void targetAddres(byte[] trama) {
        System.out.printf("Target hardware address: ");
        for (int r = 32; r < 38; r++) {     //Obtener el "la direccion MAC de la que se pregunta"
            if (r % 16 == 0) {
                // System.out.println("");
            }
            System.out.printf("%02X ", trama[r]);
        }
        System.out.println("");
        System.out.printf("Target protocol address: ");
        for (int r = 38; r < 42; r++) {     //Obtener el "la direccion IP por la que se pregunta "
            if (r % 16 == 0) {
                System.out.println("");
            }
            System.out.printf("%02X ", trama[r]);
        }
        System.out.println("\n");
    }
}
