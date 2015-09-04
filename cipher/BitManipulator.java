package cipher;

import java.util.ArrayList;
import java.util.List;

/**
 * 
 * @author doug Rohde
 *
 */
public class BitManipulator {
	//for manipulating as a String
	public static int[] initialPermutationArr = new int[] {58, 50, 42, 34, 26, 18, 10, 2,
		 60, 52, 44, 36, 28, 20, 12, 4,
		 62, 54, 46, 38, 30, 22, 14, 6,
		 64, 56, 48, 40, 32, 24, 16, 8,
		 57, 49, 41, 33, 25, 17, 9, 1,
		 59, 51, 43, 35, 27, 19, 11, 3,
		 61, 53, 45, 37, 29, 21, 13, 5,
		 63, 55, 47, 39, 31, 23, 15, 7};
	
	public static int[] permutationFunction = new int[] {16, 7, 20, 21,
														29, 12, 28, 17, 
														1, 15, 23, 26,
														5, 18, 31, 10, 
														2, 8, 24, 14, 
														32, 27, 3, 9,
														19, 13, 30, 6,
														22, 11, 4, 25};
	
	public static int[] permutedChoiceOne = new int[] { 57, 49, 41, 33, 25, 17, 9,
														1, 58, 50, 42, 34, 26, 18,
														10, 2, 59, 51, 43, 35, 27,
														19, 11, 3, 60, 52, 44, 36,
														63, 55, 47, 39, 31, 23, 15,
														7, 62, 54, 46, 38, 30, 22,
														14, 6, 61, 53, 45, 37, 29,
														21, 13, 5, 28, 20, 12, 4};
	
	public static int[] permutedChoiceTwo = new int[] {14, 17, 11, 24, 1, 5,
														3, 28, 15, 6, 21, 10,
														23, 19, 12, 4, 26, 8,
														16, 7, 27, 20, 13, 2,
														41, 52, 31, 37, 47, 55,
														30, 40, 51, 45, 33, 48,
														44, 49, 39, 56, 34, 53,
														46, 42, 50, 36, 29, 32};
	
	public static int[] EbitSelection = new int[]{32, 1, 2, 3, 4, 5,
													4, 5, 6, 7, 8, 9,
													8, 9, 10, 11, 12, 13,
													12, 13, 14, 15, 16, 17,
													16, 17, 18, 19, 20, 21,
													20, 21, 22, 23, 24, 25, 
													24, 25, 26, 27, 28, 29,
													28, 29, 30, 31, 32, 1 };
													
	
														
	private static byte[] keyShifts = new byte[]{1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
	
	public static int[] inversePermutation = new int[]{40, 8, 48, 16, 56, 24, 64, 32,
														39, 7, 47, 15, 55, 23, 63, 31,
														38, 6, 46, 14, 54, 22, 62, 30,
														37, 5, 45, 13, 53, 21, 61, 29, 
														36, 4, 44, 12, 52, 20, 60, 28,
														35, 3, 43, 11, 51, 19, 59, 27,
														34, 2, 42, 10, 50, 18, 58, 26,
														33, 1, 41, 9, 49, 17, 57, 25};
	
	/*
	public BitManipulator (long number){
		this.bitString = Long.toBinaryString(number);
	}
	*/
	/**
	 * Takes in a bitString and then shifts the bits as per the guide
	 * in the given shift array.
	 * @param bitString
	 * @param shiftArray
	 * @return String bitString
	 */
	public static String shiftStringBits(String bitString, int[] shiftArray){
		String permutedString = "";
		char[] originalArray = bitString.toCharArray();
				
		char tmpChar;
		int shiftPlace;
		for(int i =0;i<shiftArray.length;i++){ 
			//Where the bit should be shifted to
			shiftPlace = shiftArray[i]-1;
			
			tmpChar = originalArray[shiftPlace];
			//put the bit found to the right of last bit 
			permutedString += tmpChar;
			
		}
		//permutedString = Arrays.toString(permutedArray);
		//permutedString = permutedString.replace(", ", "");
		return permutedString;
	}
	
	/**
	 * Get permutation from given sBoxes 
	 * @param RorK
	 * @param sBoxes
	 * @return
	 */
	public static long getPermutationFromSBoxes(long RorK, byte[][][] sBoxes){		
		String newBitString = "";
		String RorKbitString = String.format("%48s", Long.toBinaryString(RorK)).replace(' ', '0');
		String tmpBits;
		String rowBits;
		String columnBits;
		String tmpBitString;
		int rowNum;
		int columnNum;
		int tmpNum=0;
		int position=0;
		int sNum=0;
		//Iterate over 6 bits at a time
		while(position < RorKbitString.length()){
			rowBits = "";
			columnBits = "";
			int range= position +6;
			//get next 6 bits
			tmpBits = RorKbitString.substring(position, range);
			//get row from outer two bits.
			rowBits += tmpBits.charAt(0)+""+tmpBits.charAt(tmpBits.length() -1);
			rowNum = Integer.parseInt(rowBits,2);
			
			//Column bits from inner 4 bits
			columnBits += tmpBits.charAt(1)+""+tmpBits.charAt(2)+""+tmpBits.charAt(3)+""+tmpBits.charAt(4);
			columnNum = Integer.parseInt(columnBits,2);
			//look up sboxes to use with row and column nums
			tmpNum=sBoxes[sNum][rowNum][columnNum];
			tmpBitString = String.format("%4s",Integer.toBinaryString(tmpNum)).replace(' ', '0');
			newBitString += tmpBitString;
			position = range;
			sNum++;
		}
		
		
		return Long.parseLong(newBitString,2);
	}
	
	
	/**
	 * rotates 56 bit CD String the num of bits relevant for the iteration, 
	 * puts result through permuted choice 2
	 * @param CD
	 * @param iteration
	 * @return
	 */
	public static String performCDShiftandPermutate(String CD, int iteration){
		List<String> CDList = BitManipulator.splitBitStrings(CD);
		String C = String.format("%28s", CDList.get(0)).replace(' ', '0');
		String D = String.format("%28s", CDList.get(1)).replace(' ', '0');
	
		long numC = Integer.parseInt(C, 2);
		long numD = Integer.parseInt(D, 2);
		
		//numD = Long.rotateLeft(numD, keyShifts[iteration]);
		//rotates bits around the 28 bits in the number
		numC = (numC << keyShifts[iteration]) | (numC>>> (28-keyShifts[iteration]));
		numD = (numD << keyShifts[iteration]) | (numD>>> (28-keyShifts[iteration]));
		//Only get the 28 bits of the number as a bit string, get rid of twos compliment
		C = String.format("%28s",Long.toBinaryString(numC & 0xFFFFFFF)).replace(' ', '0');
		D = String.format("%28s", Long.toBinaryString(numD & 0xFFFFFFF )).replace(' ', '0');
		
		

		CD = C+D;
		
		
		return CD;
	}
	
	
	/**
	 * splits bitstring into two halves, L and R
	 * @param bitString
	 * @return ArrayList<String> bitstrings broken up
	 */
	public static List<String> splitBitStrings(String bitString){
		List<String> LR = new ArrayList<String>();
		String L = bitString.substring(0,(bitString.length()/2));
		String R = bitString.substring((bitString.length()/2),bitString.length());
		LR.add(L);
		LR.add(R);
		
		return LR;

	}
}
