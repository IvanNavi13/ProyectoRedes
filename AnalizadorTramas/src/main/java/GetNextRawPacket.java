/* interfaz 2*/
import com.sun.jna.Platform;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.PcapStat;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.NifSelector;

import org.pcap4j.packet.IpV4Packet;

@SuppressWarnings("javadoc")
public class GetNextRawPacket {

    private static final String COUNT_KEY = GetNextRawPacket.class.getName() + ".count";
    private static final int COUNT = Integer.getInteger(COUNT_KEY, 5);

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

    public static void main(String[] args) throws PcapNativeException, NotOpenException {
        String filter = args.length != 0 ? args[0] : "";

        System.out.println(COUNT_KEY + ": " + COUNT);
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

        PcapHandle handle
                = new PcapHandle.Builder(nif.getName())
                        .snaplen(SNAPLEN)
                        .promiscuousMode(PromiscuousMode.PROMISCUOUS)
                        .timeoutMillis(READ_TIMEOUT)
                        .bufferSize(BUFFER_SIZE)
                        .build();

        handle.setFilter(filter, BpfCompileMode.OPTIMIZE);

        int num = 0;
        while (true) {
            byte[] packet = handle.getNextRawPacket();
            if (packet == null) {
                continue;
            } else {
                System.out.println(handle.getTimestamp());
                System.out.println(ByteArrays.toHexString(packet, " "));
                for (int j = 0; j < packet.length; j++) {
                    System.out.printf("%02X ", packet[j]);
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
                System.out.println("\nTipo" + tipo);

                switch (tipo) {

                    case (int) 2054: {             //   ----------------------------->Encabezado IP 
                        System.out.println("-------------> Tipo ARP <---------------");
                        hardwareType(packet);
                        protocolType(packet);
                        hardwareAdressLength(packet);
                        protocolAdressLength(packet);
                        opCode(packet);
                        senderAddres(packet);
                        targetAddres(packet);
                    }

                    case (int) 2048: {            //   ----------------------------->Encabezado IP 
                        System.out.println("-------------> Tipo IP <---------------");
                        try {
                            //IP
                            int ihl = (packet[14] & 0x0f) * 4;
                            //Campo IHL
                            System.out.println("Tam paquete IP:" + ihl + " bytes");
                            byte[] tmp_ip = Arrays.copyOfRange(packet, 14, 14 + ihl); // Creo una copia solo del encabezado IP, apartir del byte 14
                            IpV4Packet ip = IpV4Packet.newPacket(tmp_ip, 0, tmp_ip.length);
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

                        } catch (IllegalRawDataException ex) {
                            Logger.getLogger(GetNextRawPacket.class.getName()).log(Level.SEVERE, null, ex);
                        }

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

        PcapStat ps = handle.getStats();
        System.out.println("ps_recv: " + ps.getNumPacketsReceived());
        System.out.println("ps_drop: " + ps.getNumPacketsDropped());
        System.out.println("ps_ifdrop: " + ps.getNumPacketsDroppedByIf());
        if (Platform.isWindows()) {
            System.out.println("bs_capt: " + ps.getNumPacketsCaptured());
        }

        handle.close();
    }

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

    /*----------------------------------------------------------------------------------------------------TIPO ARP-----------------------------------------------------------------------*/
    public static void hardwareType(byte[] trama) {
        System.out.printf("Tipo de Hardware: ");
        for (int r = 14; r < 16; r++) {     //Obtener el tipo de hardware, en este caso tiene que ser 1 
            if (r % 16 == 0) {
                System.out.println("");
            }
            System.out.printf("%02X ", trama[r]);

        }

    }

    public static void protocolType(byte[] trama) {
        System.out.printf("Tipo de Protocolo: ");
        for (int r = 16; r < 18; r++) {     //Obtener el tipo de protocolo, en este caso tiene que ser 0x0800 
            if (r % 16 == 0) {
                System.out.println("");
            }
            System.out.printf("%02X ", trama[r]);

        }
    }

    public static void hardwareAdressLength(byte[] trama) {
        System.out.printf("Tamaño de la direccion fisica: ");
        for (int r = 18; r < 19; r++) {     //Obtener el tamaño de la direccion fisica, en este caso tiene que ser 0x06 
            if (r % 16 == 0) {
                System.out.println("");
            }
            System.out.printf("%02X ", trama[r]);

        }
    }

    public static void protocolAdressLength(byte[] trama) {
        System.out.printf("Tamaño del protocolo: ");
        for (int r = 19; r < 20; r++) {     //Obtener el tamaño de la direccion ip(protocolo IP), en este caso tiene que ser 0x04 
            if (r % 16 == 0) {
                System.out.println("");
            }
            System.out.printf("%02X ", trama[r]);
        }

    }

    public static void opCode(byte[] trama) {
        System.out.printf("Codigo de operacion: ");
        for (int r = 20; r < 22; r++) {     //Obtener el tipo de peticion
            if (r % 16 == 0) {
                System.out.println("");
            }
            System.out.printf("%02X ", trama[r]);

        }
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
        System.out.printf("Sender protocol address: ");
        for (int r = 28; r < 32; r++) {     //Obtener el "la direccion de quien esta preguntando , direccion IP"
            if (r % 16 == 0) {
                System.out.println("");
            }
            System.out.printf("%02X ", trama[r]);
        }
    }

    public static void targetAddres(byte[] trama) {
        System.out.printf("Target hardware address: ");
        for (int r = 32; r < 38; r++) {     //Obtener el "la direccion MAC de la que se pregunta"
            if (r % 16 == 0) {
                System.out.println("");
            }
            System.out.printf("%02X ", trama[r]);
        }
        System.out.printf("Target protocol address: ");
        for (int r = 38; r < 42; r++) {     //Obtener el "la direccion IP por la que se pregunta "
            if (r % 16 == 0) {
                System.out.println("");
            }
            System.out.printf("%02X ", trama[r]);
        }
    }
}
