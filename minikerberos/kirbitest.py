from ccache import CCACHE

kirbi = 'C:\\Users\\base\\Desktop\\mimikatz\\x64\\'
cc = CCACHE.from_kirbidir(kirbi)
cc.to_file('test3.ccache')