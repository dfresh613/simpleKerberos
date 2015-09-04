package kerberos;


import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Random;

import cipher.CBC;
import cipher.DES;

/**
 * Abstract helper class for userserver keyserver and userclient
 * @author derohde
 *
 */
public abstract class ServerObject {
	protected int server_port;
	protected Socket clientSocket;
	protected DataInputStream sockIn;
	protected ServerSocket serverSocket;
	protected DataOutputStream sockOut;
	protected DES desCipher;
	protected byte[] session_key;
	protected CBC cbc;
	protected byte[] user_key;

	public ServerObject() {
		desCipher = new DES("sboxes_default");
		this.cbc = new CBC(desCipher);
	}

	/**
	 * parses hex key to byte array
	 * @param hexKey
	 * @return byte array
	 */
	protected byte[] parseHexKeyToByteArray(String hexKey) {
		byte[] keyByteArr = new byte[8];
		int x = 0;
		for (int i = 0; i + 1 < hexKey.length(); i += 2) {
			keyByteArr[x] = (byte) Integer.parseInt(hexKey.substring(i, i + 2),
					16);
			x++;
		}
		return keyByteArr;
	}

	/**
	 * Generates random 64 bit long number
	 * @return long
	 */
	protected long randomNum() {
		Random numGenerator = new Random();
		long randomLong = 0x0L;
		int randomNum = numGenerator.nextInt();
		int randomNum2 = numGenerator.nextInt();
		randomLong = (randomLong << 32) | (randomNum & 0xFFFFFFFFL);
		randomLong = (randomLong << 32) | (randomNum2 & 0xFFFFFFFFL);
		return randomLong;
	}

	/**
	 * Used to copy a smaller array into a larger array, starting from a num,
	 * leaving the other entries as they were (not copying arrays)
	 * 
	 * @param largerArray
	 * @param smallerArray
	 * @param largerArrayStartIdx
	 * @return
	 */
	public byte[] copyIntoArray(byte[] largerArray, byte[] smallerArray,
			int largerArrayStartIdx) {
		for (int i = 0; i < smallerArray.length; i++) {
			largerArray[largerArrayStartIdx + i] = smallerArray[i];
		}
		return largerArray;
	}

	/**
	 * Convert a 64-bit byte array to a long.
	 * 
	 * @param block
	 *            the 64-bit block as a byte array
	 * @return the block as a long
	 */
	protected long byteArrayToLong(byte[] block) {
		long lock = 0L;
		for (int i = 0; i < 8; i++)
			lock = (lock << 8) | (block[i] & 0xFFL);
		return lock;
	}

	/**
	 * Convert 4 digit port to byte array
	 * @param number
	 * @return
	 */
	protected byte[] portToByteArray(int number) {
		byte[] block = new byte[2];
		for (int i = 1; i >= 0; i--) {
			block[i] = (byte) (number & 0xFF);
			number = number >> 8;
		}
		return block;

	}

	/**
	 * Encrypt the outgoing message, and send it through the socket
	 * @param message
	 */
	protected void encryptMessage(byte[] message) {
		// number of bytes that will be appended for padding
		int numAppendBytes = 8 - (message.length % 8);
		// messsage length + append bytes
		long iv = message.length + numAppendBytes;
		cbc.setIV(longToByteArray(iv));
		byte[] encryptedMessage = cbc.encrypt(session_key, message);
		try {
			sockOut.write(encryptedMessage);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			System.out.println("Connection Reset");
		}
	}
/**
 * Decrypt incoming message through in socket
 * @param message
 */
	protected void decryptMessage(byte[] message) {
		byte[] iv = new byte[8];
		// v=Arrays.copyOf(message,8);

		// byte[] messageContent = new byte[(int) byteArrayToLong(iv)];

		String messageText = new String(cbc.decrypt(session_key, message));
		System.out.println(messageText);
	}

	/**
	 * Recieves, decrypts and sets session key
	 * @param message
	 */
	protected void receiveSessionKey(byte[] message) {

		byte[] sessionKey = desCipher.decrypt(user_key, message);
		this.session_key = sessionKey;
		// }else{
		// decryptMessage(Arrays.copyOfRange(message,8,message.length));

	}

	// decryptMessage(Arrays.copyOfRange(message,8,message.length));

	/**
	 * Convert a 64-bit long to a byte array.
	 * 
	 * @param lock
	 *            the 64-bit block as a long
	 * @return the block as a byte array
	 */
	protected byte[] longToByteArray(long lock) {
		byte[] block = new byte[8];
		for (int i = 7; i >= 0; i--) {
			block[i] = (byte) (lock & 0xFFL);
			lock = lock >> 8;
		}
		return block;
	}
}
