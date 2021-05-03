package marshal.state;

import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.state.impl.InMemoryIdentityKeyStore;
import org.whispersystems.libsignal.state.impl.InMemoryPreKeyStore;
import org.whispersystems.libsignal.state.impl.InMemorySignedPreKeyStore;

public class MarshalProtocolStore {

	private final InMemoryPreKeyStore preKeyStore = new InMemoryPreKeyStore();
	private final InMemorySignedPreKeyStore signedPreKeyStore = new InMemorySignedPreKeyStore();
	private final InMemoryIdentityKeyStore identityKeyStore;
	private final ECKeyPair marshalSignatureKeyPair;
	private final byte[] marshalSignatureKeySignature;
	private final MarshalSessionStore sessionStore = new MarshalSessionStore();
	private ECKeyPair initMarshalCrossUserRatchetKeyPair;
	
	public MarshalProtocolStore(IdentityKeyPair identityKeyPair, int localRegistrationId, ECKeyPair marshalSignatureKeyPair) throws InvalidKeyException {
		this.identityKeyStore = new InMemoryIdentityKeyStore(identityKeyPair, localRegistrationId);
		this.marshalSignatureKeyPair = marshalSignatureKeyPair;
		this.marshalSignatureKeySignature = Curve.calculateSignature(identityKeyPair.getPrivateKey(), marshalSignatureKeyPair.getPublicKey().serialize());
	}
	
	public IdentityKeyPair getIdentityKeyPair() {
		return this.identityKeyStore.getIdentityKeyPair();
	}
	
	public ECKeyPair getMarshalSignatureKeyPair() {
		return this.marshalSignatureKeyPair;
	}
	
	public byte[] getMarshalSignatureKeySignature() {
		return marshalSignatureKeySignature;
	}

	public void storePreKey(int preKeyId, PreKeyRecord record) {
		this.preKeyStore.storePreKey(preKeyId, record);
	}
	
	public PreKeyRecord loadPreKey(int preKeyId) throws InvalidKeyIdException {
		return this.preKeyStore.loadPreKey(preKeyId);
	}
	
	public void storeSignedPreKey(int signedPreKeyId, SignedPreKeyRecord record) {
		this.signedPreKeyStore.storeSignedPreKey(signedPreKeyId, record);
	}
	
	public SignedPreKeyRecord loadSignedPreKey(int signedPreKeyId) throws InvalidKeyIdException {
		return this.signedPreKeyStore.loadSignedPreKey(signedPreKeyId);
	}
	
	public void storeSession(SignalProtocolAddress address, MarshalSession session) {
		this.sessionStore.storeSession(address, session);
	}
	
	public MarshalSession loadSession(SignalProtocolAddress address) {
		return this.sessionStore.loadSession(address);
	}

	public ECKeyPair getInitMarshalCrossUserRatchetKeyPair() {
		return initMarshalCrossUserRatchetKeyPair;
	}

	public void setInitMarshalCrossUserRatchetKeyPair(ECKeyPair initMarshalCrossUserRatchetKeyPair) {
		this.initMarshalCrossUserRatchetKeyPair = initMarshalCrossUserRatchetKeyPair;
	}
	
}
