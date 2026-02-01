# implementation for the actual luhn algorithm to find missing digit 'X'

import sys

def luhns(num_str):
    """
    Calculates the missing digit 'X' in a number string to satisfy the Luhn algorithm checksum.
    
    This function processes the input string (representing a card number or similar) 
    where 'X' is an unknown digit. It computes the checksum of the known digits according 
    to the Luhn algorithm rules (doubling every second digit from the left - index 0, 2, etc.) 
    and determines what value 'X' must have for the total sum to be divisible by 10.
    """
    sum = 0
    isOdd = False 
    for i in range(len(num_str)):
        char = num_str[i]
        if char != 'X':
            if (i % 2 == 0):
                # Even indices: double the number
                n = int(char)*2
                if len(str(n)) == 2:
                    # If doubling results in two digits, add the sum of digits
                    sum += int(str(n)[0]) + int(str(n)[1])
                else:
                    sum += n
            else:
                # Odd indices: add the number as is
                sum += int(char)
        else:
            if (i % 2 == 0):
                # If X is at an even index, it will be subject to the doubling rule
                isOdd = True
    
    # Calculate what value is needed to make the sum a multiple of 10
    rest = (10 - (sum % 10)) % 10

    if isOdd:
        # If X is at an even index, we need to reverse the doubling logic.
        # Doubled values mapping: 
        # val: 0 1 2 3 4 5 6 7 8 9
        # res: 0 2 4 6 8 1 3 5 7 9
        
        if (rest % 2 == 1):
            # If the needed remainder is odd, it corresponds to original digits 5-9
            # Math trick to reverse the digit summing
            result = int(f'1{rest-1}')/2
        else:
            # If the needed remainder is even, it corresponds to original digits 0-4
            result = rest/2
    else:
        # If X is at an odd index, it contributes its value directly
        result = rest
    return  int(result)

if __name__ == "__main__":
    # Usage: python luhns.py <filename>
    # Reads a file containing number strings with 'X' and prints the sequence of found X digits.
    filename = sys.argv[1]
    output = ""
    with open(filename, 'r') as f:
        for line in f:
            if line.strip():
                output += str(luhns(line.strip()))
    print(output)