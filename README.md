# Windows Update Denial of Service POC

Reproduced on Windows 7 (patched to June 2021). I believe it reproduces on Windows Server 2016.

Notified to MSRC. Closed as might fix in future.

# Summary

A zero length Content-Length header returned to a Windows Update HEAD request causes svchost to write to disk in an infinite loop. This uses up to 100% of disk availability.

# Description

Various Windows Update mechanisms use Windows Update and the BITS service to request update patches. This includes Microsoft Security Essentials, which requests signature updates using this mechanism. Part of the requirements of any Windows Update proxy server is that the HTTP server's HEAD method must return the file size, and its GET method must support the Content-Range and Content-Length headers.

However, a transparent proxy can be configured to respond to HEAD requests to download.windowsupdate.com with a malformed response, one where the "Content-Length" header is set to "0". When this happens, the following activity takes place:

1. Windows Update returns an error (eg: Code 8024AFFF)

2. Resource Monitor shows svchost (netsvcs) making repeated writes to the files below. Each write is synced to disk and the writes continue indefinitely. This causes significant disk activity.

        C:\ProgramData\Microsoft\Network\Downloader\qmgr0.dat
        C:\ProgramData\Microsoft\Network\Downloader\qmgr1.dat

The write loop continues indefinitely or until the bits services is halted (using "net stop bits"). The infinite loop is an effective denial of service.

I have seen Internet Service Providers (eg: Vodafone Ireland's 4G network) with misconfigured proxy servers that do return a zero Content-Length header for any HEAD request. This is effectively a DDOS attack on the entire network (or at least on my machines!).

# Proof of Concept

See `proof_of_concept.pdf` and `contentlength.py`.

In summary, a Linux machine is configured to act as a "Internet WiFi hotspot". In this form, Linux is acting as a router to the internet. For this PoC, I'm calling the WiFi internet "wlan0".

1. IPTables is configured to redirect all port 80 requests to a proxy listening on port 8080:

        $ sudo iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 80 -j REDIRECT --to-port 8080

2. The "mitmdump" tool (Part of the mitmproxy toolset at https://mitmproxy.org/) is run in transparent mode in conjunction with a Python script (contentlength.py) that transforms specific responses from the windowsupdate server:

        $ ./mitmdump --mode transparent --showhost -s contentlength.py
        Loading script contentlength.py
        Proxy server listening at http://*:8080
        ...

3. A Windows machine is connected to the hotspot and the operator either:

    - Waits for MSE to update (it does this daily when the "last updated" time is exceeded) or 

    - Uses Windows Update, set to “Never check for Updates”, to check for pending updates (ie: a manual check for patches). A pending patch is selected and installation attempted. I find the “Windows Malicious Software Removal Tool” to be very handy for this purpose.


# Observed Result

The mitmdump process on the Linux server prints a message to confirm:

     Msdownload HEAD of len 2003400 seen and set to 0

The issue described in the "Description" above occurs immediately. Detailed information including images is set out in the accompanying proof_of_concept.pdf document.

The 100% disk usage can be immediately halted with `net stop bits` run in an elevated command console.

