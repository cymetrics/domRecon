class bcolors:
    PLAIN = '\033[97m'
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_header(data, quiet):
    if quiet:
        return
    tabs = "="
    spacing = " "
    num = 40 - (len(data) + 2)
    leftt = int((num - (num%2))/2)
    right = int((num + (num%2))/2)
    print(bcolors.BOLD + tabs*leftt + spacing + data + spacing + tabs*right + bcolors.ENDC)

if __name__ == "__main__":
    print(bcolors.HEADER, "Testing colors")
    print(bcolors.PLAIN, "This is PLAIN")
    print(bcolors.OKBLUE, "This is OKBLUE")
    print(bcolors.OKCYAN, "This is OKCYAN")
    print(bcolors.OKGREEN, "This is OKGREEN")
    print(bcolors.WARNING, "This is WARNING")
    print(bcolors.FAIL, "This is FAIL")
    print(bcolors.ENDC, "This is ENDC")
    print(bcolors.BOLD, "This is BOLD")
    print(bcolors.UNDERLINE, "This is UNDERLINE")