package kerberos;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.net.UnknownHostException;

public class UserClient extends ServerObject {
	private String ks_host;
	private int ks_port;
	private String other_host;
	private int other_port;
	private Integer user_port;
	boolean sessionKeyReceived = false;
	boolean run = true;

	
	public static void main(String[] args) {
		UserClient us = new UserClient(args);
	}

	/**
	 * Constructor defines host, port, other_host, other_port, user_port, user_key from args
	 * @param args
	 */
	public UserClient(String[] args) {
		super();
		this.ks_host = args[0];
		this.ks_port = Integer.parseInt(args[1]);
		this.other_host = args[2];
		this.other_port = Integer.parseInt(args[3]);
		this.user_port = Integer.parseInt(args[4]);
		this.user_key = parseHexKeyToByteArray(args[5]);
		try {
			//System.out.println("Opening socket to keyserver");
			// create local print writer for client, using the output stream
			// from the socket.Same for buffered
			// reader
			clientSocket = new Socket(ks_host, ks_port);
			sockOut = new DataOutputStream(clientSocket.getOutputStream());
			sockIn = new DataInputStream(clientSocket.getInputStream());
			BufferedReader standardIn = new BufferedReader(
					new InputStreamReader(System.in));
			sendSessionKeyRequest();
			Byte bytes;

			while (run) {

				while ((bytes = sockIn.readByte()) != null) {
					if (!sessionKeyReceived) {
						// receive sessionKey...hard coded to lenth 8 since we
						// know that's # of bytes of the original sesison key.
						byte[] sessionKeyBytes = new byte[8];
						sessionKeyBytes[0] = bytes;
						for (int i = 1; i < 8; i++) {
							sessionKeyBytes[i] = sockIn.readByte();
						}
						receiveSessionKey(sessionKeyBytes);
						// Now collect the rest of the bytes, and get ready to
						// send them to the userserver.
						for (int i = 0; i < 8; i++) {
							sessionKeyBytes[i] = sockIn.readByte();
						}
						clientSocket.close();
						clientSocket = new Socket(other_host, other_port);
						sockOut = new DataOutputStream(
								clientSocket.getOutputStream());
						sockIn = new DataInputStream(
								clientSocket.getInputStream());
						// now decrypt the other session key with this users
						// private key and send it to userserver
						sockOut.write(desCipher.decrypt(user_key,
								sessionKeyBytes));
						sessionKeyReceived = true;
						String userInput;
						while ((userInput = standardIn.readLine()) != null
								&& sessionKeyReceived) {
							byte[] inputBytes = userInput.getBytes();
							encryptMessage(inputBytes);
							break;
						}
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

		} catch (UnknownHostException e) {
			System.out.println("Unable to find host");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			System.out.println("Connection reset..");
		} finally {
			System.out.println("Closing socket to keyserver");
			// clientSocket.close();
		}

	}

	/**
	 * Send session key request out to keyserver
	 */
	private void sendSessionKeyRequest() {
		//System.out.println("Attempting to get session key");
		byte[] keyRequest = new byte[4];
		byte[] other_port_bytes = portToByteArray(other_port);
		byte[] user_port_bytes = portToByteArray(user_port);
		keyRequest = copyIntoArray(keyRequest, user_port_bytes, 0);
		keyRequest = copyIntoArray(keyRequest, other_port_bytes, 2);
		try {
			sockOut.write(keyRequest);
		} catch (IOException e) {
			System.out.println("connection reset..");
		}
	}

}
