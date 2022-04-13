
// Algoritmo de Knuth-Morris-Pratt para buscar un "patron" en un byte array.

public class KPM {
/**
* Busca en el byte array, la primera ocurrencia del byte array "patron".
*  
*/
public static int indexOf(byte[] data, byte[] pattern) {

		int[] failure = computeFailure(pattern);
 
		int j = 0;
 
		for (int i = 0; i < data.length; i++) {
	
			while (j > 0 && pattern[j] != data[i]) {
				j = failure[j - 1];
			}

			if (pattern[j] == data[i]) {
				j++;
			}

			if (j == pattern.length) {
				return i - pattern.length + 1;
			}
		}
		return -1;
}
 
/**
      * computeFailure
*
*/
static private int[] computeFailure(byte[] pattern) {

	int[] failure = new int[pattern.length];

	int j = 0;

	for (int i = 1; i < pattern.length; i++) {

		while (j>0 && pattern[j] != pattern[i]) {

			j = failure[j - 1];

		}

		if (pattern[j] == pattern[i]) {

			j++;

		}

		failure[i] = j;

	}
	return failure;
}
}