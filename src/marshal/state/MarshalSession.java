package marshal.state;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPublicKey;

public class MarshalSession {
	
	private ECKeyPair ephemeralKeyPair;
	
	private int remotePreKeyId;
	private int remoteSignedPreKeyId;
	private IdentityKey remoteIdentityKey;
	private ECPublicKey remoteSignedPreKey;
	private ECPublicKey remotePreKey;

	private ECKeyPair initSameUserRatchetKey;
	
	private ECPublicKey remoteMarshalSignatureKey;
	
	private ECPublicKey remoteCrossUserRatchetKey;
	private ECKeyPair localCrossUserRatchetKey;
	
	private byte[] listChainRatchetKeys;
	private byte[] chainKey;
	
	private int countX;
	private int countY;
	
	public MarshalSession() {}
	
	public void setChainKey(byte[] chainKey) {
		this.chainKey = chainKey;
	}
	
	public byte[] getChainKey() {
		return this.chainKey;
	}

	public ECKeyPair getEphemeralKeyPair() {
		return ephemeralKeyPair;
	}

	public void setEphemeralKeyPair(ECKeyPair ephemeralKeyPair) {
		this.ephemeralKeyPair = ephemeralKeyPair;
	}

	public ECPublicKey getRemoteCrossUserRatchetKey() {
		return remoteCrossUserRatchetKey;
	}

	public void setRemoteCrossUserRatchetKey(ECPublicKey remoteCrossUserRatchetKey) {
		this.remoteCrossUserRatchetKey = remoteCrossUserRatchetKey;
	}

	public ECKeyPair getLocalCrossUserRatchetKey() {
		return localCrossUserRatchetKey;
	}

	public void setLocalCrossUserRatchetKey(ECKeyPair localCrossUserRatchetKey) {
		this.localCrossUserRatchetKey = localCrossUserRatchetKey;
	}

	public IdentityKey getRemoteIdentityKey() {
		return remoteIdentityKey;
	}

	public void setRemoteIdentityKey(IdentityKey remoteIdentityKey) {
		this.remoteIdentityKey = remoteIdentityKey;
	}

	public ECPublicKey getRemoteSignedPreKey() {
		return remoteSignedPreKey;
	}

	public void setRemoteSignedPreKey(ECPublicKey remoteSignedPreKey) {
		this.remoteSignedPreKey = remoteSignedPreKey;
	}

	public ECPublicKey getRemotePreKey() {
		return remotePreKey;
	}

	public void setRemotePreKey(ECPublicKey remotePreKey) {
		this.remotePreKey = remotePreKey;
	}

	public ECKeyPair getInitSameUserRatchetKey() {
		return initSameUserRatchetKey;
	}

	public void setInitSameUserRatchetKey(ECKeyPair initSameUserRatchetKey) {
		this.initSameUserRatchetKey = initSameUserRatchetKey;
	}

	public int getRemotePreKeyId() {
		return remotePreKeyId;
	}

	public void setRemotePreKeyId(int remotePreKeyId) {
		this.remotePreKeyId = remotePreKeyId;
	}

	public int getRemoteSignedPreKeyStoreId() {
		return remoteSignedPreKeyId;
	}

	public void setRemoteSignedPreKeyId(int remoteSignedPreKeyId) {
		this.remoteSignedPreKeyId = remoteSignedPreKeyId;
	}

	public int getCountX() {
		return countX;
	}

	public void setCountX(int countX) {
		this.countX = countX;
	}

	public int getCountY() {
		return countY;
	}

	public void setCountY(int countY) {
		this.countY = countY;
	}

	public int getRemoteSignedPreKeyId() {
		return remoteSignedPreKeyId;
	}

	public ECPublicKey getRemoteMarshalSignatureKey() {
		return remoteMarshalSignatureKey;
	}

	public void setRemoteMarshalSignatureKey(ECPublicKey remoteMarshalSignatureKey) {
		this.remoteMarshalSignatureKey = remoteMarshalSignatureKey;
	}

	public byte[] getListChainRatchetKeys() {
		return listChainRatchetKeys;
	}

	public void setListChainRatchetKeys(byte[] listChainRatchetKeys) {
		this.listChainRatchetKeys = listChainRatchetKeys;
	}
	
}
