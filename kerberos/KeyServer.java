package kerberos;


import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.util.HashMap;


public class KeyServer extends ServerObject {

	private HashMap<Integer, byte[]> userKeyMappings = new HashMap<Integer, byte[]>();
	boolean run = true;

	public static void main(String[] args) {
		KeyServer ks = new KeyServer(args);
	}
	/**
	 * Constructor takes in args to determine port
	 * @param args
	 */
	public KeyServer(String[] args) {
		super();
		server_port = Integer.parseInt(args[0]);
		// iterate every two arguments, to stoer user, key info.
		for (int i = 1; i < args.length; i += 2) {
			byte[] keyByteArr = parseHexKeyToByteArray(args[i + 1]);
			long test = byteArrayToLong(keyByteArr);
			this.userKeyMappings.put(Integer.parseInt(args[i]), keyByteArr);
		}
		initializeServer();
	}

	/**
	 * Initialize listening on socket
	 */
	private void initializeServer() {
		try {
			serverSocket = new ServerSocket(server_port);
			clientSocket = serverSocket.accept();
			sockOut = new DataOutputStream(clientSocket.getOutputStream());
			sockIn = new DataInputStream(clientSocket.getInputStream());
			// statically setting length of byte, since keyserver always accepts
			// the same amount of bytes for request
			byte[] message = new byte[4];
			System.out.println("Listening...");
			Byte bytes;
			while ((bytes = sockIn.readByte()) != null) {
				message[0] = bytes;
				for (int i = 1; i < 4; i++) {
					message[i] = sockIn.readByte();
				}
				sendServerKey(message);
			}

			/*
			 * while(run){ sockIn.readFully(message); if(!message.equals(new
			 * byte[4])){ sendServerKey(message); } }
			 */

		} catch (IOException e) {
			System.out.println("Unable to listen to connections on port: "
					+ server_port);
		} finally {
			// sockOut.close();
		}
	}

	/**
	 * Send session key to requested client
	 * @param message
	 */
	private void sendServerKey(byte[] message) {
		byte[] sessionInfo = new byte[16];
		// interpret first byte of message. make sure it's a request key byte
		int userA = 0;
		int userB = 0;

		for (int i = 0; i < 2; i++) {
			userA = (userA << 8) | (message[i] & 0xFF);
		}

		for (int i = 2; i < 4; i++) {
			userB = (userB << 8) | (message[i] & 0xFF);
		}

		System.out.println("userA requesting session: " + userA);
		System.out.println("userB requesting session:" + userB);
		long sessionKey = randomNum();
		byte[] userAEncryptedSes = desCipher.encrypt(
				userKeyMappings.get(userA), longToByteArray(sessionKey));
		byte[] userBEncryptedSes = desCipher.encrypt(
				userKeyMappings.get(userA),
				desCipher.encrypt(userKeyMappings.get(userB),
						longToByteArray(sessionKey)));

		sessionInfo = copyIntoArray(sessionInfo, userAEncryptedSes, 0);
		sessionInfo = copyIntoArray(sessionInfo, userBEncryptedSes, 8);
		try {
			this.sockOut.write(sessionInfo);
		} catch (IOException e) {
			System.out.println("Reset connection...");
		}
	}

}
