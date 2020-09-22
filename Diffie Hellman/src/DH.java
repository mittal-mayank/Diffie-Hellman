import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Random;

public class DH {

	private static BigInteger prime = new BigInteger("100000000000000000000000000000000000000109");
	// ^^ non-secret large prime number
	private static int generator = 2;
	// ^^ non-secret primitive root modulo of the prime number
	private BigInteger pckey;
	// ^^ non-secret user key
	private BigInteger prkey;
	// ^^ secret user key
	private static BigInteger secret = BigInteger.valueOf(generator);
	// ^^ common secret among the users
	private static ArrayList<DH> members = new ArrayList<DH>();
	// ^^ list of all members participating in the key exchange

	public DH(int length) {
		members.add(this);
		setPrKey(length);
		setPcKey();
		setSecret();
	}
	// ^^ constructor creating the user with the bit size of secret user key being
	// == length

	private static void setSecret() {
		secret = secret.modPow(members.get(members.size() - 1).prkey, prime);
	}

	// ^^ recalculating the common secret when a user is created
	private static void refreshSecret() {
		BigInteger temp = new BigInteger("1");
		for (int i = 0; i < members.size(); i++) {
			temp.multiply(members.get(i).prkey);
		}
		secret = BigInteger.valueOf(generator).modPow(temp, prime);
	}

	// ^^ recalculating the secret when a user is removed
	private void setPrKey(int length) {
		Random rnd = new Random();
		prkey = new BigInteger(length, 16, rnd);
	}

	// ^^ generating secret user key
	private void setPcKey() {
		pckey = BigInteger.valueOf(generator).modPow(prkey, prime);
	}
	// ^^ generating non-secret user key

	public static void removeUser(DH user) {
		members.remove(user);
		refreshSecret();
	}

	// ^^ remove a user
	public static void getPrime() {
		System.out.println(prime);
	}

	public static void getGenerator() {
		System.out.println(generator);
	}

	public void getPcKey() {
		System.out.println(pckey);
	}

	public static void getMembersSize() {
		System.out.println(members.size());
	}

	// ^^ printing non-secret values
	public static String encryption(String input) {
		String encrypText = "";
		int keyItr = 0;
		for (int i = 0; i < input.length(); i++) {
			int temp = input.charAt(i) ^ secret.toString().charAt(keyItr);
			encrypText += String.format("%02x", (byte) temp);
			keyItr++;
			if (keyItr >= input.length()) {
				keyItr = 0;
				// ^^ repeating the key once it has been used
			}
		}
		return encrypText;
	}

	// ^^ encryption using XOR cipher algorithm
	public static String decryption(String input) {
		String hexToDeci = "";
		for (int i = 0; i < input.length() - 1; i += 2) {
			String output = input.substring(i, (i + 2));
			int decimal = Integer.parseInt(output, 16);
			hexToDeci += (char) decimal;
		}
		String decrypText = "";
		int keyItr = 0;
		for (int i = 0; i < hexToDeci.length(); i++) {
			int temp = hexToDeci.charAt(i) ^ secret.toString().charAt(keyItr);
			decrypText += (char) temp;
			keyItr++;
			if (keyItr >= secret.toString().length()) {
				keyItr = 0;
				// ^^ repeating the key once it has been used
			}
		}
		return decrypText;
	}
	// ^^ decryption using XOR cipher algorithm

}