from mitmproxy import ctx
import mitmproxy.http
import mitmproxy.addonmanager
from datetime import datetime

#Use: mitmproxy -r [dump_path] -s FindTokens.py --set filename=[output_file_name] token=[token_value]
#dump_name is the mitmproxy dump file path.
#output_file_name is the name give to output files. Optional. Default: Output
#token_value token value to find in body. Default: 10
#After closing mitmproxy a file couple "filename.csv" and "filename.mf.csv" will be generated.

class Finder:
    def __init__(self):
        self.num = 0
        self.currentId = 1
        self.calls = []


    def getCallIndex(self, call):
        i = 0
        for x in self.calls:
            if x.call == call:
                return i
            i = i + 1
        else:
            return None

    def writeToFile(self):
        with open(ctx.options.filename, 'w') as f:
            f.write(f"Searching Token {ctx.options.token}:\n")
            for item in self.calls:
                f.write("%s\n" % item.__str__())


    def load(self, loader):
        loader.add_option(
            name = "filename",
            typespec = str,
            default = "Output.txt",
            help = "Name of output file",
        )
        loader.add_option(
            name = "token",
            typespec = str,
            default = "",
            help = "Token value to find",
        )

    def request(self, flow: mitmproxy.http.HTTPFlow):
        url = flow.request.url
        method = flow.request.method
        time = datetime.fromtimestamp(flow.request.timestamp_start)
        body = flow.request.text
        header = flow.request.headers
        for key, value in header.items():           
            if ctx.options.token in value: 
                self.calls.append(CallEntry(url, method, time, f"header:{key}"))
        if ctx.options.token in body:
            self.calls.append(CallEntry(url, method, time, "body"))


    def done(self):
        self.writeToFile()


class CallEntry:

    def __init__(self,call,method,time,where):
        super().__init__()
        self.method = method
        self.call = call
        self.time = time
        self.where = where

    def __str__(self):
        return f"Found in {self.where} of {self.method} {self.call} at {self.time}"

    def __repr__(self):
        return self.__str__()

addons = [
    Finder()
]