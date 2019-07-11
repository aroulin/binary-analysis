import crypt
import string

def testPass(cryptPass, dictFile):
    """
    Crack linux /etc/shadow password a dictionary file
    :param str cryptPass: password in linux /etc/passwd format
                          e.g., $6$salt$hashed_password
    :param str dictFile: dictionary file

    Prints the cracked password, if found, to std out
    """

    # password format: $num$salt$hashed_password
    # fields          0  1   2      3

    if len(cryptPass.split('$')) < 4:
        return

    dict = open(dictFile, 'r')
    crypt_salt = string.join(cryptPass.split('$')[0:3], '$')
    for word in dict.readlines():
        word = word.strip('\n')
        cryptWord = crypt.crypt(word, crypt_salt)
        if (cryptWord == cryptPass):
            print "[+] Found Password: "+word+"\n"
            return
    print "[-] Password Not Found.\n"
    return


def main():
    passFile = open('passwords.txt')
    for line in passFile.readlines():
        if ":" in line:
            user = line.split(':')[0]
            cryptPass = line.split(':')[1]
            print "[*] Cracking Password For: "+user
            testPass(cryptPass, "dictionary.txt")

if __name__ == "__main__":
    main()
