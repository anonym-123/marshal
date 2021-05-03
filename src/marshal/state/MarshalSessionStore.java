package marshal.state;

import java.util.HashMap;
import java.util.Map;

import org.whispersystems.libsignal.SignalProtocolAddress;

public class MarshalSessionStore {
	
	private Map<SignalProtocolAddress, MarshalSession> sessions = new HashMap<>();
	
	public MarshalSessionStore() {}
	
	public MarshalSession loadSession(SignalProtocolAddress remoteAddress) {
		if(sessions.containsKey(remoteAddress)) {
			return sessions.get(remoteAddress);
		} else {
			return new MarshalSession();
		}
	}
	
	public void storeSession(SignalProtocolAddress address, MarshalSession session) {
		sessions.put(address, session);
	}

}
