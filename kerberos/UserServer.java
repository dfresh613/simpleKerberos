package kerberos;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ServerSocket;
;

public class UserServer extends ServerObject {

	boolean run = true;

	public static void main(String[] args) {
		UserServer us = new UserServer(args);
	}

	/**
	 * Constructor initializing port and key
	 * @param args
	 */
	public UserServer(String[] args) {
		super();
		server_port = Integer.parseInt(args[0]);
		this.user_key = parseHexKeyToByteArray(args[1]);
		initializeServer();
	}

	/**
	 * initializes listening on server ports
	 */
	private void initializeServer() {
		boolean connected = false;
		try {
			BufferedReader standardIn = new BufferedReader(
					new InputStreamReader(System.in));
			serverSocket = new ServerSocket(server_port);
			clientSocket = serverSocket.accept();
			sockOut = new DataOutputStream(clientSocket.getOutputStream());
			sockIn = new DataInputStream(clientSocket.getInputStream());
			Byte bytes;
			System.out.println("Listening...");
			byte[] sessionKeyBytes = new byte[8];

			while (run) {
				while ((bytes = sockIn.readByte()) != null) {

					// get sesison key if this is the first time connecting
					if (!connected) {
						// if not connected with a session key, grab the first 8
						// bytes, receive the sesion key.
						sessionKeyBytes[0] = bytes;
						for (int i = 1; i < 8; i++) {
							sessionKeyBytes[i] = sockIn.readByte();
						}
						receiveSessionKey(sessionKeyBytes);
						connected = true;
					} else {
						// now that we have the session key and are connected to
						// the client, decrypt all sent messages
						// get the first byte to determine lenth.
						byte[] iv = new byte[8];
						iv[0] = bytes;
						for (int i = 1; i < 8; i++) {
							iv[i] = sockIn.readByte();
						}
						int messageLen = (int) byteArrayToLong(iv) + 8;
						byte[] message = new byte[messageLen];
						copyIntoArray(message, iv, 0);
						for (int i = 8; i < messageLen; i++) {
							// build message from bytes being readin.
							message[i] = sockIn.readByte();
						}
						decryptMessage(message);
						break;

					}

				}

				String userInput;
				while ((userInput = standardIn.readLine()) != null) {
					byte[] inputBytes = userInput.getBytes();
					encryptMessage(inputBytes);
					break;
				}
			}

		} catch (IOException e) {
			System.out.println("Unable to listen to connections on port: "
					+ server_port);
		} finally {
			// sockOut.close();
		}
	}

}
