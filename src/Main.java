import java.io.IOException;
import java.security.SignatureException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.whispersystems.libsignal.DuplicateMessageException;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.InvalidVersionException;
import org.whispersystems.libsignal.LegacyMessageException;
import org.whispersystems.libsignal.NoSessionException;
import org.whispersystems.libsignal.SessionBuilder;
import org.whispersystems.libsignal.SessionCipher;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.UntrustedIdentityException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.protocol.PreKeySignalMessage;
import org.whispersystems.libsignal.protocol.SignalMessage;
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.state.impl.InMemorySignalProtocolStore;
import org.whispersystems.libsignal.util.KeyHelper;

import marshal.MarshalSessionBuilder;
import marshal.MarshalSessionCipher;
import marshal.protocol.MarshalMessage;
import marshal.protocol.MarshalPreKeyMessage;
import marshal.state.MarshalPreKeyBundle;
import marshal.state.MarshalProtocolStore;
import marshal.utils.MarshalUtils;

public class Main {

	private static final SignalProtocolAddress ALICE_ADDRESS = new SignalProtocolAddress("+14151111111", 1);
	private static final SignalProtocolAddress BOB_ADDRESS = new SignalProtocolAddress("+14152222222", 1);

	public static void scenario_marshal() throws InvalidKeyException, InvalidKeyIdException, SignatureException {

		// Create and initialize Bob Store
		MarshalProtocolStore bobStore = new MarshalProtocolStore(KeyHelper.generateIdentityKeyPair(),
				KeyHelper.generateRegistrationId(false), Curve.generateKeyPair());
		int bobPreKeyId = KeyHelper.getRandomSequence(Integer.MAX_VALUE);
		int bobSignedPreKeyId = KeyHelper.getRandomSequence(Integer.MAX_VALUE);
		ECKeyPair bobPreKeyPair = Curve.generateKeyPair();
		ECKeyPair bobSignedPreKeyPair = Curve.generateKeyPair();
		byte[] bobSignedPreKeySignature = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(),
				bobSignedPreKeyPair.getPublicKey().serialize());
		ECKeyPair bobinitMarshalCrossUserRatchetKeyPair = Curve.generateKeyPair();
		bobStore.setInitMarshalCrossUserRatchetKeyPair(bobinitMarshalCrossUserRatchetKeyPair);
		bobStore.storePreKey(bobPreKeyId, new PreKeyRecord(bobPreKeyId, bobPreKeyPair));
		bobStore.storeSignedPreKey(bobSignedPreKeyId, new SignedPreKeyRecord(bobSignedPreKeyId,
				System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

		// Bob create PreKeyBundle
		MarshalPreKeyBundle bobPreKeyBundle = new MarshalPreKeyBundle(bobPreKeyId, bobPreKeyPair.getPublicKey(),
				bobSignedPreKeyId, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
				bobStore.getIdentityKeyPair().getPublicKey(), bobinitMarshalCrossUserRatchetKeyPair.getPublicKey());

		// Alice retrieve Bob PreKeyBundle and initialize a session with Bob
		// PreKeyBundle
		MarshalProtocolStore aliceStore = new MarshalProtocolStore(KeyHelper.generateIdentityKeyPair(),
				KeyHelper.generateRegistrationId(false), Curve.generateKeyPair());
		MarshalSessionBuilder aliceSessionBuilder = new MarshalSessionBuilder(aliceStore, BOB_ADDRESS);
		aliceSessionBuilder.process(bobPreKeyBundle);

		// Alice encrypt first message for Bob
		MarshalSessionCipher aliceSessionCipher = new MarshalSessionCipher(aliceStore, BOB_ADDRESS);
		MarshalPreKeyMessage messageA_1_1 = aliceSessionCipher.encryptPreKeyMessage("Alice message x1 y1.".getBytes());

		// Bob receive Alice PreKeyMessage and initialize from his side with the
		// PreKeyMessage
		MarshalSessionBuilder bobSessionBuilder = new MarshalSessionBuilder(bobStore, ALICE_ADDRESS);
		bobSessionBuilder.process(messageA_1_1);

		// Bob decrypt PreKeyMessage
		MarshalSessionCipher bobSessionCipher = new MarshalSessionCipher(bobStore, ALICE_ADDRESS);
		byte[] plaintext = bobSessionCipher.decryptPreKeyMessage(messageA_1_1);
		// System.out.println(new String(plaintext));

		// Bob encrypt PreKeyMessage response
		MarshalPreKeyMessage messageB_1_2 = bobSessionCipher
				.encryptPreKeyMessageResponse("Bob message x1 y2.".getBytes());

		// Alice decrypt Bob response
		plaintext = aliceSessionCipher.decryptPreKeyMessageResponse(messageB_1_2);
		// System.out.println(new String(plaintext));

		// Alice encrypt 3 messages
		MarshalMessage messageA_1_3 = aliceSessionCipher.encrypt("Alice message x1 y3".getBytes(), true);
		MarshalMessage messageA_2_3 = aliceSessionCipher.encrypt("Alice message x2 y3".getBytes(), false);
		MarshalMessage messageA_3_3 = aliceSessionCipher.encrypt("Alice message x3 y3".getBytes(), false);

		// Bob decrypt 3 message
		plaintext = bobSessionCipher.decrypt(messageA_1_3, true);
		// System.out.println(new String(plaintext));
		plaintext = bobSessionCipher.decrypt(messageA_2_3, false);
		// System.out.println(new String(plaintext));
		plaintext = bobSessionCipher.decrypt(messageA_3_3, false);
		// System.out.println(new String(plaintext));

		// Bob encrypt 3 message
		MarshalMessage messageB_1_4 = bobSessionCipher.encrypt("Bob message x1 y4".getBytes(), true);
		MarshalMessage messageB_2_4 = bobSessionCipher.encrypt("Bob message x2 y4".getBytes(), false);
		MarshalMessage messageB_3_4 = bobSessionCipher.encrypt("Bob message x3 y4".getBytes(), false);

		// Bob decrypt 3 message
		plaintext = aliceSessionCipher.decrypt(messageB_1_4, true);
		// System.out.println(new String(plaintext));
		plaintext = aliceSessionCipher.decrypt(messageB_2_4, false);
		// System.out.println(new String(plaintext));
		plaintext = aliceSessionCipher.decrypt(messageB_3_4, false);
		// System.out.println(new String(plaintext));

	}

	public static void scenario_signal()
			throws InvalidKeyException, UntrustedIdentityException, InvalidMessageException, InvalidVersionException,
			DuplicateMessageException, LegacyMessageException, InvalidKeyIdException, NoSessionException {

		// Bob create store and PreKey bundle
		SignalProtocolStore bobStore = new InMemorySignalProtocolStore(KeyHelper.generateIdentityKeyPair(),
				KeyHelper.generateRegistrationId(false));
		ECKeyPair bobPreKeyPair = Curve.generateKeyPair();
		ECKeyPair bobSignedPreKeyPair = Curve.generateKeyPair();
		byte[] bobSignedPreKeySignature = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(),
				bobSignedPreKeyPair.getPublicKey().serialize());
		PreKeyBundle bobPreKey = new PreKeyBundle(bobStore.getLocalRegistrationId(), 1, 31337,
				bobPreKeyPair.getPublicKey(), 22, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
				bobStore.getIdentityKeyPair().getPublicKey());
		bobStore.storePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
		bobStore.storeSignedPreKey(22,
				new SignedPreKeyRecord(22, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

		// Alice retrieve Bob PreKeyBundle and initialize a session with Bob
		// PreKeyBundle
		SignalProtocolStore aliceStore = new InMemorySignalProtocolStore(KeyHelper.generateIdentityKeyPair(),
				KeyHelper.generateRegistrationId(false));
		SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
		aliceSessionBuilder.process(bobPreKey);

		// Alice encrypt first message for Bob
		SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
		String message_A1 = "Alice message x1 y1.";
		CiphertextMessage outgoingMessage_A1 = aliceSessionCipher.encrypt(message_A1.getBytes());

		// Bob receive Alice PreKeyMessage initialize session and decrypt message
		PreKeySignalMessage incomingMessage_A1 = new PreKeySignalMessage(outgoingMessage_A1.serialize());
		SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);
		byte[] plaintext = bobSessionCipher.decrypt(incomingMessage_A1);
		// System.out.println(new String(plaintext));

		// Bob encrypt response
		CiphertextMessage outgoingMessage_B1 = bobSessionCipher.encrypt("Bob message x1 y2.".getBytes());

		// Alice decrypt bob message
		SignalMessage incomingMessage_B1 = new SignalMessage(outgoingMessage_B1.serialize());
		plaintext = aliceSessionCipher.decrypt(incomingMessage_B1);
		// System.out.println(new String(plaintext));

		// Alice encrypt 3 message
		CiphertextMessage outgoingMessage_A2_1 = aliceSessionCipher.encrypt("Alice message x1 y3.".getBytes());
		CiphertextMessage outgoingMessage_A2_2 = aliceSessionCipher.encrypt("Alice message x2 y3.".getBytes());
		CiphertextMessage outgoingMessage_A2_3 = aliceSessionCipher.encrypt("Alice message x3 y3.".getBytes());

		// Bob decrypt 3 Alice message
		SignalMessage incomingMessage_A2_1 = new SignalMessage(outgoingMessage_A2_1.serialize());
		plaintext = bobSessionCipher.decrypt(incomingMessage_A2_1);
		byte[] plaintext_2 = bobSessionCipher.decrypt(new SignalMessage(outgoingMessage_A2_2.serialize()));
		byte[] plaintext_3 = bobSessionCipher.decrypt(new SignalMessage(outgoingMessage_A2_3.serialize()));
		/*
		 * System.out.println(new String(plaintext)); System.out.println(new
		 * String(plaintext_2)); System.out.println(new String(plaintext_3));
		 */

		// Bob encrypt 3 message
		CiphertextMessage outgoingMessage_B2_1 = bobSessionCipher.encrypt("Bob message x1 y4".getBytes());
		CiphertextMessage outgoingMessage_B2_2 = bobSessionCipher.encrypt("Bob message x2 y4.".getBytes());
		CiphertextMessage outgoingMessage_B2_3 = bobSessionCipher.encrypt("Bob message x3 y4.".getBytes());

		// Alice decrypt Bob message
		SignalMessage incomingMessage_B2_1 = new SignalMessage(outgoingMessage_B2_1.serialize());
		plaintext = aliceSessionCipher.decrypt(incomingMessage_B2_1);
		plaintext_2 = aliceSessionCipher.decrypt(new SignalMessage(outgoingMessage_B2_2.serialize()));
		plaintext_3 = aliceSessionCipher.decrypt(new SignalMessage(outgoingMessage_B2_3.serialize()));
		/*
		 * System.out.println(new String(plaintext)); System.out.println(new
		 * String(plaintext_2)); System.out.println(new String(plaintext_3));
		 */

	}

	public static void marshal_session_setup() throws InvalidKeyException, InvalidKeyIdException, SignatureException {

		// Create and initialize Bob Store
		MarshalProtocolStore bobStore = new MarshalProtocolStore(KeyHelper.generateIdentityKeyPair(),
				KeyHelper.generateRegistrationId(false), Curve.generateKeyPair());
		int bobPreKeyId = KeyHelper.getRandomSequence(Integer.MAX_VALUE);
		int bobSignedPreKeyId = KeyHelper.getRandomSequence(Integer.MAX_VALUE);
		ECKeyPair bobPreKeyPair = Curve.generateKeyPair();
		ECKeyPair bobSignedPreKeyPair = Curve.generateKeyPair();
		byte[] bobSignedPreKeySignature = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(),
				bobSignedPreKeyPair.getPublicKey().serialize());
		ECKeyPair bobinitMarshalCrossUserRatchetKeyPair = Curve.generateKeyPair();
		bobStore.setInitMarshalCrossUserRatchetKeyPair(bobinitMarshalCrossUserRatchetKeyPair);
		bobStore.storePreKey(bobPreKeyId, new PreKeyRecord(bobPreKeyId, bobPreKeyPair));
		bobStore.storeSignedPreKey(bobSignedPreKeyId, new SignedPreKeyRecord(bobSignedPreKeyId,
				System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

		// Bob create PreKeyBundle
		MarshalPreKeyBundle bobPreKeyBundle = new MarshalPreKeyBundle(bobPreKeyId, bobPreKeyPair.getPublicKey(),
				bobSignedPreKeyId, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
				bobStore.getIdentityKeyPair().getPublicKey(), bobinitMarshalCrossUserRatchetKeyPair.getPublicKey());

		// Alice retrieve Bob PreKeyBundle and initialize a session with Bob
		// PreKeyBundle
		MarshalProtocolStore aliceStore = new MarshalProtocolStore(KeyHelper.generateIdentityKeyPair(),
				KeyHelper.generateRegistrationId(false), Curve.generateKeyPair());
		MarshalSessionBuilder aliceSessionBuilder = new MarshalSessionBuilder(aliceStore, BOB_ADDRESS);
		aliceSessionBuilder.process(bobPreKeyBundle);

		// Alice encrypt first message for Bob
		MarshalSessionCipher aliceSessionCipher = new MarshalSessionCipher(aliceStore, BOB_ADDRESS);
		MarshalPreKeyMessage messageA_1_1 = aliceSessionCipher.encryptPreKeyMessage("Alice message x1 y1.".getBytes());

		// Bob receive Alice PreKeyMessage and initialize from his side with the
		// PreKeyMessage
		MarshalSessionBuilder bobSessionBuilder = new MarshalSessionBuilder(bobStore, ALICE_ADDRESS);
		bobSessionBuilder.process(messageA_1_1);

		// Bob decrypt PreKeyMessage
		MarshalSessionCipher bobSessionCipher = new MarshalSessionCipher(bobStore, ALICE_ADDRESS);
		byte[] plaintext = bobSessionCipher.decryptPreKeyMessage(messageA_1_1);

	}

	public static void signal_session_setup()
			throws InvalidKeyException, UntrustedIdentityException, InvalidMessageException, InvalidVersionException,
			DuplicateMessageException, LegacyMessageException, InvalidKeyIdException {

		// Bob create store and PreKey bundle
		SignalProtocolStore bobStore = new InMemorySignalProtocolStore(KeyHelper.generateIdentityKeyPair(),
				KeyHelper.generateRegistrationId(false));
		ECKeyPair bobPreKeyPair = Curve.generateKeyPair();
		ECKeyPair bobSignedPreKeyPair = Curve.generateKeyPair();
		byte[] bobSignedPreKeySignature = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(),
				bobSignedPreKeyPair.getPublicKey().serialize());
		PreKeyBundle bobPreKey = new PreKeyBundle(bobStore.getLocalRegistrationId(), 1, 31337,
				bobPreKeyPair.getPublicKey(), 22, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
				bobStore.getIdentityKeyPair().getPublicKey());
		bobStore.storePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
		bobStore.storeSignedPreKey(22,
				new SignedPreKeyRecord(22, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

		// Alice retrieve Bob PreKeyBundle and initialize a session with Bob
		// PreKeyBundle
		SignalProtocolStore aliceStore = new InMemorySignalProtocolStore(KeyHelper.generateIdentityKeyPair(),
				KeyHelper.generateRegistrationId(false));
		SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
		aliceSessionBuilder.process(bobPreKey);

		// Alice encrypt first message for Bob
		SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
		String message_A1 = "Alice message x1 y1.";
		CiphertextMessage outgoingMessage_A1 = aliceSessionCipher.encrypt(message_A1.getBytes());

		// Bob receive Alice PreKeyMessage initialize session and decrypt message
		PreKeySignalMessage incomingMessage_A1 = new PreKeySignalMessage(outgoingMessage_A1.serialize());
		SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);
		byte[] plaintext = bobSessionCipher.decrypt(incomingMessage_A1);

	}

	public static void marshal_encrypt_decrypt_sameChain(MarshalSessionCipher aliceSessionCipher,
			MarshalSessionCipher bobSessionCipher, byte[] message) throws InvalidKeyException, SignatureException {

		MarshalMessage marshalMessage = aliceSessionCipher.encrypt(message, false);
		byte[] plaintext = bobSessionCipher.decrypt(marshalMessage, false);

	}

	public static void signal_encrypt_decrypt_sameChain(SessionCipher aliceSessionCipher,
			SessionCipher bobSessionCipher, byte[] message) throws UntrustedIdentityException, InvalidMessageException,
			DuplicateMessageException, LegacyMessageException, NoSessionException {

		CiphertextMessage signalMessage = aliceSessionCipher.encrypt("message".getBytes());
		byte[] plaintext = bobSessionCipher.decrypt(new SignalMessage(signalMessage.serialize()));

	}

	public static void marshal_encrypt_decrypt_newChain(MarshalSessionCipher aliceSessionCipher,
			MarshalSessionCipher bobSessionCipher, byte[] message) throws InvalidKeyException, SignatureException {

		MarshalMessage aliceMarshalMessage = aliceSessionCipher.encrypt(message, true);
		byte[] plaintext = bobSessionCipher.decrypt(aliceMarshalMessage, true);
		MarshalMessage bobMarshalMessage = bobSessionCipher.encrypt(message, true);
		plaintext = aliceSessionCipher.decrypt(bobMarshalMessage, true);

	}

	public static void signal_encrypt_decrypt_newChain(SessionCipher aliceSessionCipher, SessionCipher bobSessionCipher,
			byte[] message) throws UntrustedIdentityException, InvalidMessageException, DuplicateMessageException,
			LegacyMessageException, NoSessionException {

		CiphertextMessage bobSignalMessage = bobSessionCipher.encrypt("message".getBytes());
		byte[] plaintext = aliceSessionCipher.decrypt(new SignalMessage(bobSignalMessage.serialize()));
		CiphertextMessage aliceSignalMessage = aliceSessionCipher.encrypt("message".getBytes());
		plaintext = bobSessionCipher.decrypt(new SignalMessage(aliceSignalMessage.serialize()));

	}

	public static void test_scenario(double nb_run) throws SignatureException, InvalidKeyException,
			InvalidKeyIdException, UntrustedIdentityException, InvalidMessageException, InvalidVersionException,
			DuplicateMessageException, LegacyMessageException, NoSessionException {

		System.out.println("Run scenario : ");

		// We run the test before measurement to let the JVM load class and JIT compiled
		scenario_marshal();

		Instant start = Instant.now();
		for (int i = 0; i < nb_run; i++) {
			scenario_marshal();
		}
		Instant end = Instant.now();
		double time = Duration.between(start, end).toMillis() / nb_run;
		System.out.println("Marshal execution time : " + time + " ms");

		// We run the test before measurement to let the JVM load class and JIT compiled
		scenario_signal();

		start = Instant.now();
		for (int i = 0; i < nb_run; i++) {
			scenario_signal();
		}
		end = Instant.now();
		time = Duration.between(start, end).toMillis() / nb_run;
		System.out.println("Signal execution time : " + time + " ms");

		System.out.println();

	}

	public static void test_session_setup(double nb_run)
			throws InvalidKeyException, UntrustedIdentityException, InvalidMessageException, InvalidVersionException,
			DuplicateMessageException, LegacyMessageException, InvalidKeyIdException, SignatureException {

		System.out.println("Run session setup : ");

		// We run the test before measurement to let the JVM load class and JIT compiled
		marshal_session_setup();

		Instant start = Instant.now();
		for (int i = 0; i < nb_run; i++) {
			marshal_session_setup();
		}
		Instant end = Instant.now();
		double time = Duration.between(start, end).toMillis() / nb_run;
		System.out.println("Marshal execution time : " + time + " ms");

		// We run the test before measurement to let the JVM load class and JIT compiled
		signal_session_setup();

		start = Instant.now();
		for (int i = 0; i < nb_run; i++) {
			signal_session_setup();
		}
		end = Instant.now();
		time = Duration.between(start, end).toMillis() / nb_run;
		System.out.println("Signal execution time : " + time + " ms");

		System.out.println();

	}

	public static void test_marshal_encrypt__decrypt_sameChain(double nb_run)
			throws InvalidKeyException, InvalidKeyIdException, SignatureException {

		// Create and initialize Bob Store
		MarshalProtocolStore bobStore = new MarshalProtocolStore(KeyHelper.generateIdentityKeyPair(),
				KeyHelper.generateRegistrationId(false), Curve.generateKeyPair());
		int bobPreKeyId = KeyHelper.getRandomSequence(Integer.MAX_VALUE);
		int bobSignedPreKeyId = KeyHelper.getRandomSequence(Integer.MAX_VALUE);
		ECKeyPair bobPreKeyPair = Curve.generateKeyPair();
		ECKeyPair bobSignedPreKeyPair = Curve.generateKeyPair();
		byte[] bobSignedPreKeySignature = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(),
				bobSignedPreKeyPair.getPublicKey().serialize());
		ECKeyPair bobinitMarshalCrossUserRatchetKeyPair = Curve.generateKeyPair();
		bobStore.setInitMarshalCrossUserRatchetKeyPair(bobinitMarshalCrossUserRatchetKeyPair);
		bobStore.storePreKey(bobPreKeyId, new PreKeyRecord(bobPreKeyId, bobPreKeyPair));
		bobStore.storeSignedPreKey(bobSignedPreKeyId, new SignedPreKeyRecord(bobSignedPreKeyId,
				System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

		// Bob create PreKeyBundle
		MarshalPreKeyBundle bobPreKeyBundle = new MarshalPreKeyBundle(bobPreKeyId, bobPreKeyPair.getPublicKey(),
				bobSignedPreKeyId, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
				bobStore.getIdentityKeyPair().getPublicKey(), bobinitMarshalCrossUserRatchetKeyPair.getPublicKey());

		// Alice retrieve Bob PreKeyBundle and initialize a session with Bob
		// PreKeyBundle
		MarshalProtocolStore aliceStore = new MarshalProtocolStore(KeyHelper.generateIdentityKeyPair(),
				KeyHelper.generateRegistrationId(false), Curve.generateKeyPair());
		MarshalSessionBuilder aliceSessionBuilder = new MarshalSessionBuilder(aliceStore, BOB_ADDRESS);
		aliceSessionBuilder.process(bobPreKeyBundle);

		// Alice encrypt first message for Bob
		MarshalSessionCipher aliceSessionCipher = new MarshalSessionCipher(aliceStore, BOB_ADDRESS);
		MarshalPreKeyMessage messageA_1_1 = aliceSessionCipher.encryptPreKeyMessage("Alice message x1 y1.".getBytes());

		// Bob receive Alice PreKeyMessage and initialize from his side with the
		// PreKeyMessage
		MarshalSessionBuilder bobSessionBuilder = new MarshalSessionBuilder(bobStore, ALICE_ADDRESS);
		bobSessionBuilder.process(messageA_1_1);

		// Bob decrypt PreKeyMessage
		MarshalSessionCipher bobSessionCipher = new MarshalSessionCipher(bobStore, ALICE_ADDRESS);
		byte[] plaintext = bobSessionCipher.decryptPreKeyMessage(messageA_1_1);
		// System.out.println(new String(plaintext));

		// Bob encrypt PreKeyMessage response
		MarshalPreKeyMessage messageB_1_2 = bobSessionCipher
				.encryptPreKeyMessageResponse("Bob message x1 y2.".getBytes());

		// Alice decrypt Bob response
		plaintext = aliceSessionCipher.decryptPreKeyMessageResponse(messageB_1_2);
		// System.out.println(new String(plaintext));

		MarshalMessage messageA_1_3 = aliceSessionCipher.encrypt("Alice message x1 y3".getBytes(), true);
		plaintext = bobSessionCipher.decrypt(messageA_1_3, true);

		Instant start = Instant.now();
		for (int i = 0; i < nb_run; i++) {
			marshal_encrypt_decrypt_sameChain(aliceSessionCipher, bobSessionCipher, "message".getBytes());
		}
		Instant end = Instant.now();
		double time = Duration.between(start, end).toMillis() / nb_run;
		System.out.println("Marshal execution time : " + time + " ms");

	}

	public static void test_signal_encrypt_decrypt_sameChain(double nb_run)
			throws InvalidKeyException, UntrustedIdentityException, InvalidMessageException, InvalidVersionException,
			DuplicateMessageException, LegacyMessageException, InvalidKeyIdException, NoSessionException {

		// Bob create store and PreKey bundle
		SignalProtocolStore bobStore = new InMemorySignalProtocolStore(KeyHelper.generateIdentityKeyPair(),
				KeyHelper.generateRegistrationId(false));
		ECKeyPair bobPreKeyPair = Curve.generateKeyPair();
		ECKeyPair bobSignedPreKeyPair = Curve.generateKeyPair();
		byte[] bobSignedPreKeySignature = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(),
				bobSignedPreKeyPair.getPublicKey().serialize());
		PreKeyBundle bobPreKey = new PreKeyBundle(bobStore.getLocalRegistrationId(), 1, 31337,
				bobPreKeyPair.getPublicKey(), 22, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
				bobStore.getIdentityKeyPair().getPublicKey());
		bobStore.storePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
		bobStore.storeSignedPreKey(22,
				new SignedPreKeyRecord(22, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

		// Alice retrieve Bob PreKeyBundle and initialize a session with Bob
		// PreKeyBundle
		SignalProtocolStore aliceStore = new InMemorySignalProtocolStore(KeyHelper.generateIdentityKeyPair(),
				KeyHelper.generateRegistrationId(false));
		SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
		aliceSessionBuilder.process(bobPreKey);

		// Alice encrypt first message for Bob
		SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
		String message_A1 = "Alice message x1 y1.";
		CiphertextMessage outgoingMessage_A1 = aliceSessionCipher.encrypt(message_A1.getBytes());

		// Bob receive Alice PreKeyMessage initialize session and decrypt message
		PreKeySignalMessage incomingMessage_A1 = new PreKeySignalMessage(outgoingMessage_A1.serialize());
		SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);
		byte[] plaintext = bobSessionCipher.decrypt(incomingMessage_A1);
		// System.out.println(new String(plaintext));

		// Bob encrypt response
		CiphertextMessage outgoingMessage_B1 = bobSessionCipher.encrypt("Bob message x1 y2.".getBytes());

		// Alice decrypt bob message
		SignalMessage incomingMessage_B1 = new SignalMessage(outgoingMessage_B1.serialize());
		plaintext = aliceSessionCipher.decrypt(incomingMessage_B1);
		// System.out.println(new String(plaintext));

		CiphertextMessage outgoingMessage_A2_1 = aliceSessionCipher.encrypt("Alice message x1 y3.".getBytes());
		SignalMessage incomingMessage_A2_1 = new SignalMessage(outgoingMessage_A2_1.serialize());
		plaintext = bobSessionCipher.decrypt(incomingMessage_A2_1);

		Instant start = Instant.now();
		for (int i = 0; i < nb_run; i++) {
			signal_encrypt_decrypt_sameChain(aliceSessionCipher, bobSessionCipher, "message".getBytes());
		}
		Instant end = Instant.now();
		double time = Duration.between(start, end).toMillis() / nb_run;
		System.out.println("Signal execution time : " + time + " ms");

	}

	public static void test_marshal_encrypt__decrypt_newChain(double nb_run)
			throws InvalidKeyException, InvalidKeyIdException, SignatureException {

		// Create and initialize Bob Store
		MarshalProtocolStore bobStore = new MarshalProtocolStore(KeyHelper.generateIdentityKeyPair(),
				KeyHelper.generateRegistrationId(false), Curve.generateKeyPair());
		int bobPreKeyId = KeyHelper.getRandomSequence(Integer.MAX_VALUE);
		int bobSignedPreKeyId = KeyHelper.getRandomSequence(Integer.MAX_VALUE);
		ECKeyPair bobPreKeyPair = Curve.generateKeyPair();
		ECKeyPair bobSignedPreKeyPair = Curve.generateKeyPair();
		byte[] bobSignedPreKeySignature = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(),
				bobSignedPreKeyPair.getPublicKey().serialize());
		ECKeyPair bobinitMarshalCrossUserRatchetKeyPair = Curve.generateKeyPair();
		bobStore.setInitMarshalCrossUserRatchetKeyPair(bobinitMarshalCrossUserRatchetKeyPair);
		bobStore.storePreKey(bobPreKeyId, new PreKeyRecord(bobPreKeyId, bobPreKeyPair));
		bobStore.storeSignedPreKey(bobSignedPreKeyId, new SignedPreKeyRecord(bobSignedPreKeyId,
				System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

		// Bob create PreKeyBundle
		MarshalPreKeyBundle bobPreKeyBundle = new MarshalPreKeyBundle(bobPreKeyId, bobPreKeyPair.getPublicKey(),
				bobSignedPreKeyId, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
				bobStore.getIdentityKeyPair().getPublicKey(), bobinitMarshalCrossUserRatchetKeyPair.getPublicKey());

		// Alice retrieve Bob PreKeyBundle and initialize a session with Bob
		// PreKeyBundle
		MarshalProtocolStore aliceStore = new MarshalProtocolStore(KeyHelper.generateIdentityKeyPair(),
				KeyHelper.generateRegistrationId(false), Curve.generateKeyPair());
		MarshalSessionBuilder aliceSessionBuilder = new MarshalSessionBuilder(aliceStore, BOB_ADDRESS);
		aliceSessionBuilder.process(bobPreKeyBundle);

		// Alice encrypt first message for Bob
		MarshalSessionCipher aliceSessionCipher = new MarshalSessionCipher(aliceStore, BOB_ADDRESS);
		MarshalPreKeyMessage messageA_1_1 = aliceSessionCipher.encryptPreKeyMessage("Alice message x1 y1.".getBytes());

		// Bob receive Alice PreKeyMessage and initialize from his side with the
		// PreKeyMessage
		MarshalSessionBuilder bobSessionBuilder = new MarshalSessionBuilder(bobStore, ALICE_ADDRESS);
		bobSessionBuilder.process(messageA_1_1);

		// Bob decrypt PreKeyMessage
		MarshalSessionCipher bobSessionCipher = new MarshalSessionCipher(bobStore, ALICE_ADDRESS);
		byte[] plaintext = bobSessionCipher.decryptPreKeyMessage(messageA_1_1);
		// System.out.println(new String(plaintext));

		// Bob encrypt PreKeyMessage response
		MarshalPreKeyMessage messageB_1_2 = bobSessionCipher
				.encryptPreKeyMessageResponse("Bob message x1 y2.".getBytes());

		// Alice decrypt Bob response
		plaintext = aliceSessionCipher.decryptPreKeyMessageResponse(messageB_1_2);
		// System.out.println(new String(plaintext));

		MarshalMessage messageA_1_3 = aliceSessionCipher.encrypt("Alice message x1 y3".getBytes(), true);
		plaintext = bobSessionCipher.decrypt(messageA_1_3, true);

		nb_run = nb_run / 2;
		Instant start = Instant.now();
		for (int i = 0; i < nb_run; i++) {
			marshal_encrypt_decrypt_newChain(aliceSessionCipher, bobSessionCipher, "message".getBytes());
		}
		Instant end = Instant.now();
		double time = Duration.between(start, end).toMillis() / nb_run;
		System.out.println("Marshal execution time : " + time + " ms");

	}

	public static void test_signal_encrypt_decrypt_newChain(double nb_run)
			throws InvalidKeyException, UntrustedIdentityException, InvalidMessageException, InvalidVersionException,
			DuplicateMessageException, LegacyMessageException, InvalidKeyIdException, NoSessionException {

		// Bob create store and PreKey bundle
		SignalProtocolStore bobStore = new InMemorySignalProtocolStore(KeyHelper.generateIdentityKeyPair(),
				KeyHelper.generateRegistrationId(false));
		ECKeyPair bobPreKeyPair = Curve.generateKeyPair();
		ECKeyPair bobSignedPreKeyPair = Curve.generateKeyPair();
		byte[] bobSignedPreKeySignature = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(),
				bobSignedPreKeyPair.getPublicKey().serialize());
		PreKeyBundle bobPreKey = new PreKeyBundle(bobStore.getLocalRegistrationId(), 1, 31337,
				bobPreKeyPair.getPublicKey(), 22, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
				bobStore.getIdentityKeyPair().getPublicKey());
		bobStore.storePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
		bobStore.storeSignedPreKey(22,
				new SignedPreKeyRecord(22, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

		// Alice retrieve Bob PreKeyBundle and initialize a session with Bob
		// PreKeyBundle
		SignalProtocolStore aliceStore = new InMemorySignalProtocolStore(KeyHelper.generateIdentityKeyPair(),
				KeyHelper.generateRegistrationId(false));
		SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
		aliceSessionBuilder.process(bobPreKey);

		// Alice encrypt first message for Bob
		SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
		String message_A1 = "Alice message x1 y1.";
		CiphertextMessage outgoingMessage_A1 = aliceSessionCipher.encrypt(message_A1.getBytes());

		// Bob receive Alice PreKeyMessage initialize session and decrypt message
		PreKeySignalMessage incomingMessage_A1 = new PreKeySignalMessage(outgoingMessage_A1.serialize());
		SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);
		byte[] plaintext = bobSessionCipher.decrypt(incomingMessage_A1);
		// System.out.println(new String(plaintext));

		// Bob encrypt response
		CiphertextMessage outgoingMessage_B1 = bobSessionCipher.encrypt("Bob message x1 y2.".getBytes());

		// Alice decrypt bob message
		SignalMessage incomingMessage_B1 = new SignalMessage(outgoingMessage_B1.serialize());
		plaintext = aliceSessionCipher.decrypt(incomingMessage_B1);
		// System.out.println(new String(plaintext));

		CiphertextMessage outgoingMessage_A2_1 = aliceSessionCipher.encrypt("Alice message x1 y3.".getBytes());
		SignalMessage incomingMessage_A2_1 = new SignalMessage(outgoingMessage_A2_1.serialize());
		plaintext = bobSessionCipher.decrypt(incomingMessage_A2_1);

		nb_run = nb_run / 2;
		Instant start = Instant.now();
		for (int i = 0; i < nb_run; i++) {
			signal_encrypt_decrypt_newChain(aliceSessionCipher, bobSessionCipher, "message".getBytes());
		}
		Instant end = Instant.now();
		double time = Duration.between(start, end).toMillis() / nb_run;
		System.out.println("Signal execution time : " + time + " ms");

	}

	public static void test_marshal_evol_sameChain()
			throws InvalidKeyException, InvalidKeyIdException, SignatureException, IOException {

		// Create and initialize Bob Store
		MarshalProtocolStore bobStore = new MarshalProtocolStore(KeyHelper.generateIdentityKeyPair(),
				KeyHelper.generateRegistrationId(false), Curve.generateKeyPair());
		int bobPreKeyId = KeyHelper.getRandomSequence(Integer.MAX_VALUE);
		int bobSignedPreKeyId = KeyHelper.getRandomSequence(Integer.MAX_VALUE);
		ECKeyPair bobPreKeyPair = Curve.generateKeyPair();
		ECKeyPair bobSignedPreKeyPair = Curve.generateKeyPair();
		byte[] bobSignedPreKeySignature = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(),
				bobSignedPreKeyPair.getPublicKey().serialize());
		ECKeyPair bobinitMarshalCrossUserRatchetKeyPair = Curve.generateKeyPair();
		bobStore.setInitMarshalCrossUserRatchetKeyPair(bobinitMarshalCrossUserRatchetKeyPair);
		bobStore.storePreKey(bobPreKeyId, new PreKeyRecord(bobPreKeyId, bobPreKeyPair));
		bobStore.storeSignedPreKey(bobSignedPreKeyId, new SignedPreKeyRecord(bobSignedPreKeyId,
				System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

		// Bob create PreKeyBundle
		MarshalPreKeyBundle bobPreKeyBundle = new MarshalPreKeyBundle(bobPreKeyId, bobPreKeyPair.getPublicKey(),
				bobSignedPreKeyId, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
				bobStore.getIdentityKeyPair().getPublicKey(), bobinitMarshalCrossUserRatchetKeyPair.getPublicKey());

		// Alice retrieve Bob PreKeyBundle and initialize a session with Bob
		// PreKeyBundle
		MarshalProtocolStore aliceStore = new MarshalProtocolStore(KeyHelper.generateIdentityKeyPair(),
				KeyHelper.generateRegistrationId(false), Curve.generateKeyPair());
		MarshalSessionBuilder aliceSessionBuilder = new MarshalSessionBuilder(aliceStore, BOB_ADDRESS);
		aliceSessionBuilder.process(bobPreKeyBundle);

		// Alice encrypt first message for Bob
		MarshalSessionCipher aliceSessionCipher = new MarshalSessionCipher(aliceStore, BOB_ADDRESS);
		MarshalPreKeyMessage messageA_1_1 = aliceSessionCipher.encryptPreKeyMessage("Alice message x1 y1.".getBytes());

		// Bob receive Alice PreKeyMessage and initialize from his side with the
		// PreKeyMessage
		MarshalSessionBuilder bobSessionBuilder = new MarshalSessionBuilder(bobStore, ALICE_ADDRESS);
		bobSessionBuilder.process(messageA_1_1);

		// Bob decrypt PreKeyMessage
		MarshalSessionCipher bobSessionCipher = new MarshalSessionCipher(bobStore, ALICE_ADDRESS);
		byte[] plaintext = bobSessionCipher.decryptPreKeyMessage(messageA_1_1);
		// System.out.println(new String(plaintext));

		// Bob encrypt PreKeyMessage response
		MarshalPreKeyMessage messageB_1_2 = bobSessionCipher
				.encryptPreKeyMessageResponse("Bob message x1 y2.".getBytes());

		// Alice decrypt Bob response
		plaintext = aliceSessionCipher.decryptPreKeyMessageResponse(messageB_1_2);
		// System.out.println(new String(plaintext));

		MarshalMessage messageA_1_3 = aliceSessionCipher.encrypt("Alice message x1 y3".getBytes(), true);
		plaintext = bobSessionCipher.decrypt(messageA_1_3, true);

		List<String> results = new ArrayList<String>();
		for (int nb_message = 1; nb_message < 51; nb_message++) {
			Instant start = Instant.now();
			for (int i = 0; i < nb_message; i++) {
				marshal_encrypt_decrypt_sameChain(aliceSessionCipher, bobSessionCipher, "message".getBytes());
			}
			Instant end = Instant.now();
			long time = Duration.between(start, end).toMillis();
			results.add("" + nb_message + "," + time + "\n");
		}

		MarshalUtils.writeCSV(results, "sameChain.csv");

	}

	public static void test_marshal_evol_newChain()
			throws InvalidKeyException, InvalidKeyIdException, SignatureException, IOException {
		// Create and initialize Bob Store
		MarshalProtocolStore bobStore = new MarshalProtocolStore(KeyHelper.generateIdentityKeyPair(),
				KeyHelper.generateRegistrationId(false), Curve.generateKeyPair());
		int bobPreKeyId = KeyHelper.getRandomSequence(Integer.MAX_VALUE);
		int bobSignedPreKeyId = KeyHelper.getRandomSequence(Integer.MAX_VALUE);
		ECKeyPair bobPreKeyPair = Curve.generateKeyPair();
		ECKeyPair bobSignedPreKeyPair = Curve.generateKeyPair();
		byte[] bobSignedPreKeySignature = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(),
				bobSignedPreKeyPair.getPublicKey().serialize());
		ECKeyPair bobinitMarshalCrossUserRatchetKeyPair = Curve.generateKeyPair();
		bobStore.setInitMarshalCrossUserRatchetKeyPair(bobinitMarshalCrossUserRatchetKeyPair);
		bobStore.storePreKey(bobPreKeyId, new PreKeyRecord(bobPreKeyId, bobPreKeyPair));
		bobStore.storeSignedPreKey(bobSignedPreKeyId, new SignedPreKeyRecord(bobSignedPreKeyId,
				System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

		// Bob create PreKeyBundle
		MarshalPreKeyBundle bobPreKeyBundle = new MarshalPreKeyBundle(bobPreKeyId, bobPreKeyPair.getPublicKey(),
				bobSignedPreKeyId, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
				bobStore.getIdentityKeyPair().getPublicKey(), bobinitMarshalCrossUserRatchetKeyPair.getPublicKey());

		// Alice retrieve Bob PreKeyBundle and initialize a session with Bob
		// PreKeyBundle
		MarshalProtocolStore aliceStore = new MarshalProtocolStore(KeyHelper.generateIdentityKeyPair(),
				KeyHelper.generateRegistrationId(false), Curve.generateKeyPair());
		MarshalSessionBuilder aliceSessionBuilder = new MarshalSessionBuilder(aliceStore, BOB_ADDRESS);
		aliceSessionBuilder.process(bobPreKeyBundle);

		// Alice encrypt first message for Bob
		MarshalSessionCipher aliceSessionCipher = new MarshalSessionCipher(aliceStore, BOB_ADDRESS);
		MarshalPreKeyMessage messageA_1_1 = aliceSessionCipher.encryptPreKeyMessage("Alice message x1 y1.".getBytes());

		// Bob receive Alice PreKeyMessage and initialize from his side with the
		// PreKeyMessage
		MarshalSessionBuilder bobSessionBuilder = new MarshalSessionBuilder(bobStore, ALICE_ADDRESS);
		bobSessionBuilder.process(messageA_1_1);

		// Bob decrypt PreKeyMessage
		MarshalSessionCipher bobSessionCipher = new MarshalSessionCipher(bobStore, ALICE_ADDRESS);
		byte[] plaintext = bobSessionCipher.decryptPreKeyMessage(messageA_1_1);
		// System.out.println(new String(plaintext));

		// Bob encrypt PreKeyMessage response
		MarshalPreKeyMessage messageB_1_2 = bobSessionCipher
				.encryptPreKeyMessageResponse("Bob message x1 y2.".getBytes());

		// Alice decrypt Bob response
		plaintext = aliceSessionCipher.decryptPreKeyMessageResponse(messageB_1_2);
		// System.out.println(new String(plaintext));

		MarshalMessage messageA_1_3 = aliceSessionCipher.encrypt("Alice message x1 y3".getBytes(), true);
		plaintext = bobSessionCipher.decrypt(messageA_1_3, true);

		List<String> results = new ArrayList<String>();
		for (int nb_message = 1; nb_message < 51; nb_message++) {
			Instant start = Instant.now();
			for (int i = 0; i < nb_message; i++) {
				marshal_encrypt_decrypt_newChain(aliceSessionCipher, bobSessionCipher, "message".getBytes());
			}
			Instant end = Instant.now();
			long time = Duration.between(start, end).toMillis();
			results.add("" + nb_message + "," + time + "\n");
		}

		MarshalUtils.writeCSV(results, "newChain.csv");
	}

	public static void test_size_marshal(int nb_messages)
			throws InvalidKeyException, InvalidKeyIdException, SignatureException {

		// Create and initialize Bob Store
		MarshalProtocolStore bobStore = new MarshalProtocolStore(KeyHelper.generateIdentityKeyPair(),
				KeyHelper.generateRegistrationId(false), Curve.generateKeyPair());
		int bobPreKeyId = KeyHelper.getRandomSequence(Integer.MAX_VALUE);
		int bobSignedPreKeyId = KeyHelper.getRandomSequence(Integer.MAX_VALUE);
		ECKeyPair bobPreKeyPair = Curve.generateKeyPair();
		ECKeyPair bobSignedPreKeyPair = Curve.generateKeyPair();
		byte[] bobSignedPreKeySignature = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(),
				bobSignedPreKeyPair.getPublicKey().serialize());
		ECKeyPair bobinitMarshalCrossUserRatchetKeyPair = Curve.generateKeyPair();
		bobStore.setInitMarshalCrossUserRatchetKeyPair(bobinitMarshalCrossUserRatchetKeyPair);
		bobStore.storePreKey(bobPreKeyId, new PreKeyRecord(bobPreKeyId, bobPreKeyPair));
		bobStore.storeSignedPreKey(bobSignedPreKeyId, new SignedPreKeyRecord(bobSignedPreKeyId,
				System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

		// Bob create PreKeyBundle
		MarshalPreKeyBundle bobPreKeyBundle = new MarshalPreKeyBundle(bobPreKeyId, bobPreKeyPair.getPublicKey(),
				bobSignedPreKeyId, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
				bobStore.getIdentityKeyPair().getPublicKey(), bobinitMarshalCrossUserRatchetKeyPair.getPublicKey());

		// Alice retrieve Bob PreKeyBundle and initialize a session with Bob
		// PreKeyBundle
		MarshalProtocolStore aliceStore = new MarshalProtocolStore(KeyHelper.generateIdentityKeyPair(),
				KeyHelper.generateRegistrationId(false), Curve.generateKeyPair());
		MarshalSessionBuilder aliceSessionBuilder = new MarshalSessionBuilder(aliceStore, BOB_ADDRESS);
		aliceSessionBuilder.process(bobPreKeyBundle);

		// Alice encrypt first message for Bob
		MarshalSessionCipher aliceSessionCipher = new MarshalSessionCipher(aliceStore, BOB_ADDRESS);
		MarshalPreKeyMessage messageA_1_1 = aliceSessionCipher.encryptPreKeyMessage("Alice message x1 y1.".getBytes());

		// Bob receive Alice PreKeyMessage and initialize from his side with the
		// PreKeyMessage
		MarshalSessionBuilder bobSessionBuilder = new MarshalSessionBuilder(bobStore, ALICE_ADDRESS);
		bobSessionBuilder.process(messageA_1_1);

		// Bob decrypt PreKeyMessage
		MarshalSessionCipher bobSessionCipher = new MarshalSessionCipher(bobStore, ALICE_ADDRESS);
		byte[] plaintext = bobSessionCipher.decryptPreKeyMessage(messageA_1_1);
		// System.out.println(new String(plaintext));

		// Bob encrypt PreKeyMessage response
		MarshalPreKeyMessage messageB_1_2 = bobSessionCipher
				.encryptPreKeyMessageResponse("Bob message x1 y2.".getBytes());

		// Alice decrypt Bob response
		plaintext = aliceSessionCipher.decryptPreKeyMessageResponse(messageB_1_2);
		// System.out.println(new String(plaintext));

		// Test size
		System.out.println("Test Marshal message size : ");

		MarshalMessage messageA = aliceSessionCipher.encrypt("Alice message".getBytes(), true);
		System.out.println("Message 1 : " + ObjectSizeFetcher.getObjectSize(messageA.serialize()));

		for (int i = 1; i < nb_messages; i++) {
			messageA = aliceSessionCipher.encrypt("Alice message".getBytes(), false);
			System.out.println("Message " + (i + 1) + " : " + ObjectSizeFetcher.getObjectSize(messageA.serialize()));
		}
		System.out.println("");

	}

	public static void test_size_signal(int nb_messages)
			throws InvalidKeyException, UntrustedIdentityException, InvalidMessageException, InvalidVersionException,
			DuplicateMessageException, LegacyMessageException, InvalidKeyIdException, NoSessionException {

		// Bob create store and PreKey bundle
		SignalProtocolStore bobStore = new InMemorySignalProtocolStore(KeyHelper.generateIdentityKeyPair(),
				KeyHelper.generateRegistrationId(false));
		ECKeyPair bobPreKeyPair = Curve.generateKeyPair();
		ECKeyPair bobSignedPreKeyPair = Curve.generateKeyPair();
		byte[] bobSignedPreKeySignature = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(),
				bobSignedPreKeyPair.getPublicKey().serialize());
		PreKeyBundle bobPreKey = new PreKeyBundle(bobStore.getLocalRegistrationId(), 1, 31337,
				bobPreKeyPair.getPublicKey(), 22, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
				bobStore.getIdentityKeyPair().getPublicKey());
		bobStore.storePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
		bobStore.storeSignedPreKey(22,
				new SignedPreKeyRecord(22, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

		// Alice retrieve Bob PreKeyBundle and initialize a session with Bob
		// PreKeyBundle
		SignalProtocolStore aliceStore = new InMemorySignalProtocolStore(KeyHelper.generateIdentityKeyPair(),
				KeyHelper.generateRegistrationId(false));
		SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
		aliceSessionBuilder.process(bobPreKey);

		// Alice encrypt first message for Bob
		SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
		String message_A1 = "Alice message x1 y1.";
		CiphertextMessage outgoingMessage_A1 = aliceSessionCipher.encrypt(message_A1.getBytes());

		// Bob receive Alice PreKeyMessage initialize session and decrypt message
		PreKeySignalMessage incomingMessage_A1 = new PreKeySignalMessage(outgoingMessage_A1.serialize());
		SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);
		byte[] plaintext = bobSessionCipher.decrypt(incomingMessage_A1);
		// System.out.println(new String(plaintext));

		// Bob encrypt response
		CiphertextMessage outgoingMessage_B1 = bobSessionCipher.encrypt("Bob message x1 y2.".getBytes());

		// Alice decrypt bob message
		SignalMessage incomingMessage_B1 = new SignalMessage(outgoingMessage_B1.serialize());
		plaintext = aliceSessionCipher.decrypt(incomingMessage_B1);
		// System.out.println(new String(plaintext));

		// Test size
		System.out.println("Test Signal message size : ");
		
		CiphertextMessage messageA = aliceSessionCipher.encrypt("Alice message.".getBytes());
		SignalMessage signalMessageA = new SignalMessage(messageA.serialize());
		System.out.println("Message 1 : " + ObjectSizeFetcher.getObjectSize(signalMessageA.serialize()));

		for (int i = 1; i < nb_messages; i++) {
			messageA = aliceSessionCipher.encrypt("Alice message".getBytes());
			signalMessageA = new SignalMessage(messageA.serialize());
			System.out.println(
					"Message " + (i + 1) + " : " + ObjectSizeFetcher.getObjectSize(signalMessageA.serialize()));
		}
		System.out.println("");

	}

	public static void main(String[] args) throws InvalidKeyException, InvalidKeyIdException, SignatureException,
			UntrustedIdentityException, InvalidMessageException, InvalidVersionException, DuplicateMessageException,
			LegacyMessageException, NoSessionException, IOException {

		double nb_run = 10;

		test_scenario(nb_run);
		test_session_setup(nb_run);

		System.out.println("Run Same Chain message :");
		test_marshal_encrypt__decrypt_sameChain(nb_run);
		test_signal_encrypt_decrypt_sameChain(nb_run);
		System.out.println();

		System.out.println("Run New Chain message :");
		test_marshal_encrypt__decrypt_newChain(nb_run);
		test_signal_encrypt_decrypt_newChain(nb_run);
		System.out.println();

		System.out.println("Run Evolution tests :");
		test_marshal_evol_sameChain();
		test_marshal_evol_newChain();
		System.out.println("Evolution tests end.");
		System.out.println("");

		test_size_marshal(50);
		test_size_signal(50);

		System.out.println("END");

	}

}
