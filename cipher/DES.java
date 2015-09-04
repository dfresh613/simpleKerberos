package cipher;


import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.List;
/**
 * Performs des encryption
 * @author doug Rohde
 *
 */
public class DES extends BlockCipher64 {
	private byte[][][] subsitutionValues;

	/**
	 * reads in sboxes file, sets byte array substitutionValues using read values
	 * @param sboxesFileName
	 */
	public DES(String sboxesFileName){
		byte[] fileByteArray = readBinaryFile(sboxesFileName);
		this.subsitutionValues = substitutionValuesFromByteArray(fileByteArray);		
	}
		
	/**
	 * Method to perform encryptino on given block using given key
	 * @param key
	 * @param block
	 * @return long encryptedBlock
	 */
	public long encrypt(long key, long block){
		return cipherFunction(key,block,true);
	}
	
	/**
	 * Generic cipher function for both encrypting/decrypting. pass true or false for the 
	 * order the keystream should be read (true = encrypt, false = decrypt)
	 * @param key
	 * @param block
	 * @param keyStreamForwards
	 * @return
	 */
	public long cipherFunction(long key, long block, boolean keyStreamForwards){
		
		//First permutation
		String originalblock = String.format("%64s",Long.toBinaryString(block)).replace(' ', '0');
		long[] keySchedule = generateKeySchedule(key);
		String permutation = BitManipulator.shiftStringBits(originalblock, BitManipulator.initialPermutationArr);
		//Splitting bits into LR	
		List<String> LR = BitManipulator.splitBitStrings(permutation);
		String L = LR.get(0);
		String R = LR.get(1);
		String initialR;
		long numR;
		long tmpNum;
		long numL;
		long RorK;
		//16 iteration of shifts and functions.
		for(int i =0;i<16;i++){
			initialR = R;
			//perform Ebit selection on L
			R = BitManipulator.shiftStringBits(R, BitManipulator.EbitSelection);
			numR = Long.parseLong(R,2);
			//exclusive or R 48 bits with K first k 48 bit iteration.
			if(keyStreamForwards){
				RorK = numR ^ keySchedule[i];
			}else{
				RorK = numR ^ keySchedule[keySchedule.length - (i+1)];
			}
			//get new R  from function f(r,k)
			numR = BitManipulator.getPermutationFromSBoxes(RorK,subsitutionValues);
			R = String.format("%32s", Long.toBinaryString(numR)).replace(' ', '0');
			
			//permutate r after function			
			R=BitManipulator.shiftStringBits(R, BitManipulator.permutationFunction);
			numR = Long.parseLong(R,2);
			
			numL = Long.parseLong(L,2);
			//exclusive or numR and numL after function
			tmpNum = numL ^ numR;
			
			L=initialR;
			R = String.format("%32s", Long.toBinaryString(tmpNum)).replace(' ', '0');
			
		}
		permutation= "";
		permutation+=R;
		permutation+=L;
		
		permutation = BitManipulator.shiftStringBits(permutation, BitManipulator.inversePermutation);
		long permNum = new BigInteger(permutation,2).longValue();
		
		return permNum;
		
	}
	
	/**
	 * Generates key schedule of 48 bit keys for 16 iterations
	 * @param key
	 */
	public long[] generateKeySchedule(long key){
		long[] keySchedule = new long[16];
		String CDBitString = String.format("%64s",Long.toBinaryString(key)).replace(' ', '0');
		String keyBitString;
		//get permuted choice by compressing using PC-1. Should compress to 56 bits
		CDBitString = BitManipulator.shiftStringBits(CDBitString, BitManipulator.permutedChoiceOne);
		//iterate 16 times to get all 16 keys for key schedule
		for(int i =0; i <16; i++){			
			CDBitString = BitManipulator.performCDShiftandPermutate(CDBitString,i);
			 keyBitString = BitManipulator.shiftStringBits(CDBitString,BitManipulator.permutedChoiceTwo);
			 keySchedule[i] = Long.parseLong(keyBitString, 2);
		}
		return keySchedule;
		
	}
	/**
	 * Method to perform decryption on given block using given key
	 * same thing as encryption, but uses keyschedule in reverse order
	 * @param key
	 * @param block
	 * @return long decryptedBlock
	 */
	public long decrypt(long key, long block){
		return cipherFunction(key,block,false);		
	}
	/**
	 * Gets the sBox values from a byteArray
	 * @param byteArray
	 * @return byte[] sBox values
	 */
	private byte[][][] substitutionValuesFromByteArray(byte[] byteArray){
		//to be used for tmp Values from bitString
		byte subValue;
		byte[][][] explodedSubs = new byte[8][4][16];		
		
		int rowx=0;
		int i =0;
		int sNum = 0;
		int rowPos=0;
		for(byte tmpByte : byteArray){
			
			
			String bitString= String.format("%8s", Integer.toBinaryString(tmpByte & 0xFF)).replace(' ', '0');
					
			String firstSubBitString = bitString.substring(0, 4);
			String secondSubBitString = bitString.substring(4,8);
			//Once 16 columns are filled, increment row, reset column count
			if(rowPos>=16){
				//if 4 rows completed, then we move on to the next substitution set
				rowx++;
				if(rowx>=4){
					sNum++;
					rowx=0;
				}
				
				i=0;
				rowPos =0;
			}
			subValue = (byte) Integer.parseInt(firstSubBitString, 2);
			explodedSubs[sNum][rowx][i*2] = subValue;
			rowPos++;
			//Once 16 columns are filled, increment row, reset column count	
			if(rowPos>=16){
				//if 4 rows completed, then we move on to the next sub set
				rowx++;
				if(rowx>=4){
					sNum++;
					rowx=0;
				}
				
				i=0;
				rowPos =0;
			}
			subValue = (byte) Integer.parseInt(secondSubBitString, 2);
			explodedSubs[sNum][rowx][i*2+1] = subValue;
			rowPos++;
			/* Alternative means of getting sbox value I was experimenting with
			Integer.parseInt(secondSubBitString,2);
			//get the first 4 bit substitution value				
			byte tmpByte2 = (byte) (tmpByte>>4);	
			
			
			 Integer.toBinaryString(tmpByte2);
			// explodedSubs[i*2];
			
			subValue = explodedSubs[i*2];
			subValue = (byte) (subValue <<4);
			explodedSubs[i*2+1] = (byte) (subValue | tmpByte);	
			
			 & 0xFF
			//second half of byte is the next substitution value
		//	subValue = (byte) (tmpByte >> 4);
			*/
			i++;
			}
		
		
		return explodedSubs;
	}
	
	
	
	/**
	 * Reads given binary file into a byte array
	 * @param filePath
	 * @return byte[]
	 */
	private byte[] readBinaryFile(String filePath){
		File file = new File(filePath);
		byte[] byteArray = new byte[(int) file.length()];
		try {
			//Create inputStream from file
			InputStream inputBytes = new BufferedInputStream(new FileInputStream(filePath));
			//initialize byte array position variable, keeps track of last insereted byte position in the array
			int byteArrayPos=0;
			//byte number read keeps track of the number of bytes read from input stream
			int byteNoRead =0;
			while(byteArrayPos < byteArray.length && byteNoRead != -1){
				//read as much as possible from file into byte array, will loop and insert the next set into the next
				//available spot in array. 
				byteNoRead = inputBytes.read(byteArray, byteArrayPos, byteArray.length - byteNoRead);
				byteArrayPos = byteArrayPos+=byteNoRead;				
			}
			inputBytes.close();
			
		} catch (FileNotFoundException e) {
			System.out.println("Could not locate sboxesFile");
		} catch (IOException e) {
			System.out.println("Error reading inputStream");
		}
		
		return byteArray;
	}
}
