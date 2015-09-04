package cipher;

import java.util.Arrays;
import java.util.Random;


public class CBC implements BlockCipherMode{
	private BlockCipher bCipher;
	private byte[] IV;
	private byte[] counter = new byte[8];
	private byte[] key;
	/*
	public static void main(String[] args){
	
		DES desCipher = new DES("/home/doug/Downloads/sboxes/sboxes_default");
		CBC blockChain = new CBC(desCipher);
		//byte [] iv = { (byte)0x6a, (byte)0x92, (byte)0x6b, (byte)0xfe, (byte)0x2a, (byte)0x29, (byte)0xfa, (byte)0xc3 };
		blockChain.randomIV();
		byte[] plaintext = {(byte)0x01, (byte)0x23,  (byte)0x6a, (byte)0x92, (byte)0x6b, (byte)0xfe, (byte)0x2a, (byte)0x29, (byte)0xfa, (byte)0xc3,(byte)0xab, (byte)0xcd, (byte)0xef, (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67, (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef,(byte)0xcd, (byte)0xef};
		byte[] key = { (byte)0x6a, (byte)0x92, (byte)0x6b, (byte)0xfe, (byte)0x2a, (byte)0x29, (byte)0xfa, (byte)0xc3 };
		byte[] ciphertext = blockChain.encrypt(key, plaintext);
		byte[] ptext = blockChain.decrypt(key, ciphertext);
	}
	*/
	/**
	 * Constructs CBC object with 
	 * @param blockCipher
	 */
	public CBC(BlockCipher blockCipher){
		this.bCipher = blockCipher;
	}
	
	/**
     * Set the initialization vector to the given value.
     * @param iv the initialization vector
     */
	@Override
	public void setIV(byte[] iv) {
		this.IV = iv;
		
	}
	
	 /**
     * first create a nonce using the the date time and the current existing counter
     * then use the cipher function to create the IV.
     */
	@Override
	public void randomIV() {
		Random numGenerator = new Random();
		long randomLong = 0x0L;
		int randomNum = numGenerator.nextInt();
		int randomNum2 = numGenerator.nextInt();
		randomLong = (randomLong << 32) | (randomNum & 0xFFFFFFFFL);
		randomLong = (randomLong << 32) | (randomNum2 & 0xFFFFFFFFL);
		byte [] randomByteArr = longToByteArray(randomLong);
		setIV(randomByteArr);
		
	}
	
	  /**
     * Get the last initialization vector set or randomized.
     * @return the initialization vector
     */
	@Override
	public byte[] getIV() {
		return this.IV;
	}
	/**
	 * Used to copy a smaller array into a larger array, starting from a num, 
	 * leaving the other entries as they were (not copying arrays)
	 * @param largerArray
	 * @param smallerArray
	 * @param largerArrayStartIdx
	 * @return
	 */
	public byte[] copyIntoArray(byte[] largerArray, byte[] smallerArray,int largerArrayStartIdx){
		for (int i=0; i <smallerArray.length;i++){
			largerArray[largerArrayStartIdx+i] = smallerArray[i];
		}
		return largerArray;
	}
	/**
	 * Encryption function which encrypts blocks of plaintext
	 */
	@Override
	public byte[] encrypt(byte[] key, byte[] plaintext) {
		plaintext = padPlainText(plaintext);	
		byte [] iv = this.getIV();
		byte [] cipherText = new byte[plaintext.length+IV.length];
		byte [] block = new byte[8];
		byte [] cipherBlock = new byte[8];
		//counter for cipherText byte array
		cipherText = copyIntoArray(cipherText, iv, 0);
		int y = 8;
		for(int i =0; i< plaintext.length; i++){			
			//arrayPos is the number of bytes currently in the block
			int arrayPos= i%8;
			block[arrayPos] = plaintext[i];
			//if the array position is 7, then we have the full block to encrypt. 
			if (arrayPos == 7){
				//xor byte arrays, put through cipher function, and reset the IV to the new cipher text.
				cipherBlock = xorByteArrays(block, iv);
				cipherBlock = this.bCipher.encrypt(key, cipherBlock);
				iv=Arrays.copyOf(cipherBlock, 8);				
				for (int x=0; x<8;x++){
					cipherText[y] = cipherBlock[x];
					y++;
				}				
			}
		}
				
		return cipherText;
	}
	/**
	 * Xors byte arrays
	 * @param firstArr
	 * @param secondArr
	 * @return
	 */
	private byte[] xorByteArrays(byte[] firstArr, byte[] secondArr){
		byte [] xordArr = new byte[8];
		for(int i =0; i<firstArr.length;i++){
			xordArr[i] = (byte) (firstArr[i] ^ secondArr[i]);
		}				
		return xordArr;
	}

	/**
	 * Decryption function for decrypting blocks of cipher text
	 */
	@Override
	public byte[] decrypt(byte[] key, byte[] ciphertext) {
		//get iv block from first 8 bytes of ciphertext
		byte [] iv = new byte [8];
		byte [] block = new byte[8];
		byte [] plaintextBlock = new byte[8];
		byte [] plainText = new byte[ciphertext.length -iv.length];
		iv = Arrays.copyOf(ciphertext, 8);
		int y=0;
		
		for (int i = 8; i< ciphertext.length;i++){
			
			//arrayPos is the number of bytes currently in the block
			int arrayPos= i%8;
			block[arrayPos] = ciphertext[i];
			//if the array position is 7, then we have the full block to encrypt. 			
			if (arrayPos == 7){
				plaintextBlock = bCipher.decrypt(key, block);
				plaintextBlock = xorByteArrays(plaintextBlock,iv);
				iv=Arrays.copyOf(block, 8);	
				for (int x=0; x<8;x++){
					plainText[y] = plaintextBlock[x];
					y++;
				}				
			}
			
			
			
		}
		return unpadPlainText(plainText);
	}
	/**
	 * Pads plaintext for 64 bit blocks
	 * @param plaintext
	 * @return paddedPlaintext
	 */
	private byte[] padPlainText(byte[] plaintext){
		int numPlaintextBytes = plaintext.length;
		//First take the array size mod 8, and then subtract that value from 
		//8, this will give us the number of bytes needed to append (assuming the block size 
		//is 64 bits so it has to be a multiple of 8 bytes)
		int numAppendBytes = 8 - (numPlaintextBytes % 8);
		//if the block is already full, append the padding anyway, because why not?
		if(numAppendBytes ==0){
			numAppendBytes = 8;
		}
		byte[] paddedPlainText = new byte [numPlaintextBytes + numAppendBytes];
		paddedPlainText = Arrays.copyOf(plaintext, paddedPlainText.length);
		for(int i=0; i<numAppendBytes;i++){
			byte byteToAdd;
			//if this is the first byte we're adding, it has to be the value of 128, if not it will be a byte of all 0s
			if(i==0){
				byteToAdd = (byte) 0x80;
			}else{
				byteToAdd = (byte) 0x00;
			}
			paddedPlainText[numPlaintextBytes+i] = byteToAdd;
		}
		return paddedPlainText;
	}
	
	private byte[] unpadPlainText(byte[]plaintext){
		int numBytesToRemove=0;
		boolean stillPadded = true;
		int i=0;
		while(stillPadded){
			//remove padding if only 0s
			if(plaintext[plaintext.length-(i+1)] == (byte) 0x00){
				numBytesToRemove++;
			}else if(plaintext[plaintext.length-(i+1)] == (byte) 0x80){
				numBytesToRemove++;
				stillPadded=false;
			}
			i++;
		}
		byte [] unpadded = Arrays.copyOf(plaintext, plaintext.length-numBytesToRemove);
		return unpadded;
	}

	

    /**
     * Convert a 64-bit byte array to a long.
     *
     * @param block the 64-bit block as a byte array
     * @return the block as a long
     */
    private long byteArrayToLong(byte[] block) {
        long lock = 0L;
        for(int i = 0; i < 8; i++)
            lock = (lock << 8) | (block[i] & 0xFFL);
        return lock;
    }

    /**
     * Convert a 64-bit long to a byte array.
     *
     * @param lock the 64-bit block as a long
     * @return the block as a byte array
     */
    private byte[] longToByteArray(long lock) {
        byte[] block = new byte[8];
        for(int i = 7; i >= 0; i--) {
            block[i] = (byte)(lock & 0xFFL);
            lock = lock >> 8;
        }
        return block;
    }

}
