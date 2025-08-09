import re
import os
import uuid


def remove_comment(inputFile, outputFile):
    fdr = None
    fdw = None
    try:
        fdr = open(inputFile, 'r', encoding="utf-8")
        fdw = open(outputFile, 'w', encoding="utf-8")
        _map = {}
        outstring = ''

        line = fdr.readline()
        while line:
            while True:
                m = re.compile('\".*\"', re.S)
                _str = m.search(line)
                if None == _str:
                    outstring += line
                    break
                key = str(uuid.uuid1())
                m = re.compile('\".*\"', re.S)
                outtmp = re.sub(m, key, line, 1)
                line = outtmp
                _map[key] = _str.group(0)
            line = fdr.readline()

        m = re.compile(r'//.*')
        outtmp = re.sub(m, ' ', outstring)
        outstring = outtmp

        m = re.compile(r'/\*.*?\*/', re.S)
        outtmp = re.sub(m, ' ', outstring)
        outstring = outtmp

        for key in _map.keys():
            outstring = outstring.replace(key, _map[key])

        # Remove empty lines and lines with only whitespace
        lines = outstring.split('\n')
        cleaned_lines = []
        for line in lines:
            # Keep line if it's not empty and not just whitespace
            if line.strip():
                cleaned_lines.append(line)
        
        # Join lines back together
        outstring = '\n'.join(cleaned_lines)

        fdw.write(outstring)
    finally:
        if fdr:
            fdr.close()
        if fdw:
            fdw.close()


if __name__ == '__main__':
    original_dir = "data/smartbugs_wild"
    output_dir = "clean_source_code"
    
    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    dir = os.listdir(original_dir)
    for i in dir:
        print(i)
        remove_comment(original_dir + "/" + i, output_dir + "/" + i)