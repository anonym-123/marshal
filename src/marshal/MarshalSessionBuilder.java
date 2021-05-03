package marshal;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;

import marshal.protocol.MarshalPreKeyMessage;
import marshal.ratchet.MarshalRatchetingSession;
import marshal.state.MarshalPreKeyBundle;
import marshal.state.MarshalProtocolStore;
import marshal.state.MarshalSession;

public class MarshalSessionBuilder {
	
	private final MarshalProtocolStore store;
	private final SignalProtocolAddress remoteAddress;
	
	public MarshalSessionBuilder(MarshalProtocolStore store, SignalProtocolAddress remoteAddress) {
		this.store = store;
		this.remoteAddress = remoteAddress;
		this.store.storeSession(this.remoteAddress, new MarshalSession());
	}
	
	public void process(MarshalPreKeyBundle preKeyBundle) throws InvalidKeyException {
		
		if(preKeyBundle.getSignedPreKeyPublic() != null &&
				!Curve.verifySignature(preKeyBundle.getIdentityKey().getPublicKey(), 
								       preKeyBundle.getSignedPreKeyPublic().serialize(), 
								       preKeyBundle.getSignedPreKeySignature())) {
			throw new InvalidKeyException("Invalid signature on key");
		}
		
		ECKeyPair ephemeralKeyPair = Curve.generateKeyPair();
		ECKeyPair localCrossUserRatchetKey = Curve.generateKeyPair();
		
		MarshalSession session = this.store.loadSession(this.remoteAddress);
		session.setEphemeralKeyPair(ephemeralKeyPair);
		session.setLocalCrossUserRatchetKey(localCrossUserRatchetKey);
		session.setRemoteCrossUserRatchetKey(preKeyBundle.getInitMarshalCrossUserRatchetPublicKey());
		session.setRemoteIdentityKey(preKeyBundle.getIdentityKey());
		session.setRemotePreKey(preKeyBundle.getPreKeyPublic());
		session.setRemoteSignedPreKey(preKeyBundle.getSignedPreKeyPublic());
		session.setRemotePreKeyId(preKeyBundle.getPreKeyId());
		session.setRemoteSignedPreKeyId(preKeyBundle.getSignedPreKeyId());
		session.setCountX(1);
		session.setCountY(1);
		
		MarshalRatchetingSession.initializeAliceSession(store, session, preKeyBundle);
		
	}
	
	public void process(MarshalPreKeyMessage preKeyMessage) throws InvalidKeyException, InvalidKeyIdException {
		
		if(!Curve.verifySignature(preKeyMessage.getSenderIdentityKey(), preKeyMessage.getSenderMarshalSignatureKey().serialize(), preKeyMessage.getMarshalSignatureKeySignature())) {
			throw new InvalidKeyException("Invalid signature on signature key");
		}
		
		MarshalSession session = this.store.loadSession(remoteAddress);
		session.setRemoteIdentityKey(new IdentityKey(preKeyMessage.getSenderIdentityKey()));
		session.setRemoteMarshalSignatureKey(preKeyMessage.getSenderMarshalSignatureKey());
		session.setLocalCrossUserRatchetKey(this.store.getInitMarshalCrossUserRatchetKeyPair());
		session.setRemoteCrossUserRatchetKey(preKeyMessage.getMessage().getSenderCrossUserRatchetKey());
		session.setCountX(1);
		session.setCountY(1);
		
		MarshalRatchetingSession.initializeBobSession(this.store, session, preKeyMessage);
		
	}

}
