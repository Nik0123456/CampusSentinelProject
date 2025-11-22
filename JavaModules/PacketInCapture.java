package net.floodlightcontroller.sdn_auth_capture;

import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import java.util.ArrayList;
import java.util.List;
import java.util.Collection;
import java.util.Map;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;

import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.OFBufferId;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

import net.floodlightcontroller.core.internal.IOFSwitchService;

public class PacketInCapture implements IFloodlightModule, IOFMessageListener {

    protected static Logger logger = LoggerFactory.getLogger(PacketInCapture.class);

    protected IFloodlightProviderService floodlightProvider;
    protected IOFSwitchService switchService;

    // Configuración de switches core
    private static final String CORE_SWITCH_1_DPID = "00:00:5e:c7:6e:c6:11:4c";
    private static final int CORE_SWITCH_1_PORT = 3;

    private static final String CORE_SWITCH_2_DPID = "00:00:72:e0:80:7e:85:4c";
    private static final int CORE_SWITCH_2_PORT = 2;

    @Override
    public String getName() {
        return PacketInCapture.class.getSimpleName();
    }

    @Override
    public boolean isCallbackOrderingPrereq(OFType type, String name) {
        return false;
    }

    @Override
    public boolean isCallbackOrderingPostreq(OFType type, String name) {
        return false;
    }

    @Override
    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        if (msg.getType() != OFType.PACKET_IN) {
            return Command.CONTINUE;
        }

        OFPacketIn pi = (OFPacketIn) msg;
        Ethernet eth = new Ethernet();
        eth.deserialize(pi.getData(), 0, pi.getData().length);

        if (eth.getEtherType() != EthType.IPv4) {
            return Command.CONTINUE;
        }

        IPv4 ipv4 = (IPv4) eth.getPayload();

        // Solo interceptar paquetes destinados al portal cautivo (10.0.0.2)
        if (!ipv4.getDestinationAddress().equals(IPv4Address.of("10.0.0.2"))) {
            return Command.CONTINUE;
        }

        MacAddress srcMac = eth.getSourceMACAddress();
        IPv4Address srcIp = ipv4.getSourceAddress();
        DatapathId dpid = sw.getId();
        OFPort inPort = pi.getMatch().get(MatchField.IN_PORT);

        final String srcMacStr = srcMac.toString();
        final String srcIpStr = srcIp.toString();
        final String dpidStr = dpid.toString();
        final int inPortNum = inPort.getPortNumber();

        // Enviar datos a Flask en thread separado
        new Thread(new Runnable() {
            public void run() {
                sendToFlask(srcMacStr, srcIpStr, dpidStr, inPortNum);
            }
        }).start();

        logger.info("Packet-In capturado: IP=" + srcIpStr + ", MAC=" + srcMacStr +
                ", DPID=" + dpidStr + ", Puerto=" + inPortNum);

        // Reenviar el paquete a ambos switches core
        final byte[] packetData = eth.serialize();

        new Thread(new Runnable() {
            public void run() {
                forwardToCoreSwitches(packetData);
            }
        }).start();

        return Command.CONTINUE;
    }

    private void forwardToCoreSwitches(byte[] packetData) {
        DatapathId core1Dpid = DatapathId.of(CORE_SWITCH_1_DPID);
        DatapathId core2Dpid = DatapathId.of(CORE_SWITCH_2_DPID);

        for (IOFSwitch sw : switchService.getAllSwitchMap().values()) {
            DatapathId swDpid = sw.getId();

            // Core Switch 1
            if (swDpid.equals(core1Dpid)) {
                if (sw.isActive()) {
                    sendPacketOut(sw, packetData, OFPort.of(CORE_SWITCH_1_PORT));
                    logger.info("✓ Packet-out enviado a Core Switch 1 (puerto " + CORE_SWITCH_1_PORT + ")");
                } else {
                    logger.warn("✗ Core Switch 1 no activo");
                }
            }

            // Core Switch 2
            if (swDpid.equals(core2Dpid)) {
                if (sw.isActive()) {
                    sendPacketOut(sw, packetData, OFPort.of(CORE_SWITCH_2_PORT));
                    logger.info("✓ Packet-out enviado a Core Switch 2 (puerto " + CORE_SWITCH_2_PORT + ")");
                } else {
                    logger.warn("✗ Core Switch 2 no activo");
                }
            }
        }
    }

    private void sendPacketOut(IOFSwitch sw, byte[] packetData, OFPort outPort) {
        try {
            OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
            pob.setBufferId(OFBufferId.NO_BUFFER);
            pob.setInPort(OFPort.CONTROLLER);
            pob.setData(packetData);

            OFActionOutput.Builder actionBuilder = sw.getOFFactory().actions()
                    .buildOutput()
                    .setPort(outPort)
                    .setMaxLen(0xFFffFFff);

            List<OFAction> actions = new ArrayList<OFAction>();
            actions.add((OFAction) actionBuilder.build());

            pob.setActions(actions);
            sw.write(pob.build());

        } catch (Exception e) {
            logger.error("Error enviando packet-out: " + e.getMessage());
        }
    }

    private void sendToFlask(String mac, String ip, String dpid, int port) {
        try {
            URL url = new URL("http://127.0.0.1:5000/packetin");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);
            conn.setConnectTimeout(2000);
            conn.setReadTimeout(2000);

            String json = String.format(
                    "{\"mac\":\"%s\",\"ip\":\"%s\",\"dpid\":\"%s\",\"in_port\":%d}",
                    mac, ip, dpid, port
            );

            OutputStream os = conn.getOutputStream();
            os.write(json.getBytes("UTF-8"));
            os.close();

            int responseCode = conn.getResponseCode();
            if (responseCode == 200) {
                logger.info("Datos enviados a Flask correctamente: " + ip);
            } else {
                logger.warn("Flask respondió con código " + responseCode);
            }
            conn.disconnect();

        } catch (Exception e) {
            logger.error("Error enviando a Flask: " + e.getMessage());
        }
    }

    // ==================== MÓDULO FLOODLIGHT ====================

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        return null;
    }

    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
        return null;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        Collection<Class<? extends IFloodlightService>> l = 
            new java.util.ArrayList<Class<? extends IFloodlightService>>();
        l.add(IFloodlightProviderService.class);
        l.add(IOFSwitchService.class); // Necesario para acceder a todos los switches
        return l;
    }

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        switchService = context.getServiceImpl(IOFSwitchService.class);
    }

    @Override
    public void startUp(FloodlightModuleContext context) {
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
        logger.info("========================================");
        logger.info(" MODULO SDN AUTH CAPTURE v3.0 CARGADO");
        logger.info(" Enviando a AMBOS switches core");
        logger.info(" Core 1: " + CORE_SWITCH_1_DPID + " puerto " + CORE_SWITCH_1_PORT);
        logger.info(" Core 2: " + CORE_SWITCH_2_DPID + " puerto " + CORE_SWITCH_2_PORT);
        logger.info("========================================");
    }
}
