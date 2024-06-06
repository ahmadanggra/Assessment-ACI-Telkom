# code built based on https://gist.github.com/NWMichl/aed4b582f3f922b5e515751d6fa6d6c1
import parsing
import credential

def main():
    # disable ssl warning
    parsing.requests.packages.urllib3.disable_warnings()

    # login into apic
    apic_cookie = parsing.apic_login(apic=credential.apic_url, username=credential.apic_username, password=credential.apic_password)

    # execute function
    parsing.parsingVLANToCsv(param_apic_url=credential.apic_url,param_cookie=apic_cookie)
    parsing.parsingBdToCsv(param_apic_url=credential.apic_url,param_cookie=apic_cookie)
    parsing.parsingEpToCsv(param_apic_url=credential.apic_url,param_cookie=apic_cookie)
    parsing.parsingCdpLldpToCsv(param_apic_url=credential.apic_url,param_cookie=apic_cookie)
    parsing.parsingEpgToCsv(param_apic_url=credential.apic_url,param_cookie=apic_cookie)
    parsing.parsingIntoCsv(param_apic_url=credential.apic_url,param_cookie=apic_cookie)
    parsing.parsingPcVpcToCsv(param_apic_url=credential.apic_url,param_cookie=apic_cookie)
    parsing.parsingL2outToCsv(param_apic_url=credential.apic_url,param_cookie=apic_cookie)
    parsing.parsingL3outToCsv3(param_apic_url=credential.apic_url,param_cookie=apic_cookie)
    parsing.domToAepCSV(param_apic_url=credential.apic_url,param_cookie=apic_cookie)
    parsing.polgroupToAepCSV(param_apic_url=credential.apic_url,param_cookie=apic_cookie)
    parsing.intToPolgroupCSV(param_apic_url=credential.apic_url,param_cookie=apic_cookie)


    # logout from apic
    logout_response = parsing.apic_logout(apic=credential.apic_url, cookie=apic_cookie)

if __name__ == "__main__":
    main()

