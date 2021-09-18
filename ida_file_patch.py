import os
import idaapi
import ida_bytes
import ida_segment
import idautils
import ida_nalt
import ida_kernwin

kk=None
def find_changed_bytes():
    global kk

    changed_bytes = list()
    for s in idautils.Segments():
        seg = idaapi.getseg(s)
        kk = seg
        for ea in range(seg.start_ea, seg.end_ea ):
            if ida_bytes.is_loaded(ea):
                abyte = ida_bytes.get_byte(ea)
                original_byte = ida_bytes.get_original_byte(ea)
                if abyte != original_byte:
                    changed_bytes.append( (ea, abyte, original_byte) )            
    return changed_bytes



def patch_file(data, changed_bytes):
    
    for ea, abyte, original_byte in changed_bytes:
        print ('%08x: %02x original(%02x)' % (ea, abyte, original_byte))
                
        file_offset = idaapi.get_fileregion_offset( ea )
        
        if data[ file_offset ] == original_byte:
            data[ file_offset ] = abyte
        else:
            raise Exception("Sth Wrong, input binary offset:value is not matched with ida ea:value!")
    
    patched_file = ida_kernwin.ask_file( 1, '*.*', 'Choose new file')
    if patched_file:
        with open(patched_file, 'wb') as f:
            f.write(bytes(data) )



def main():
    print ('Finding changed bytes...')
    changed_bytes = find_changed_bytes()
    print ('done. %d changed bytes found' % len(changed_bytes))
    
    if changed_bytes:
        original_file = ida_nalt.get_input_file_path()
        print (original_file)
    
        if not os.path.exists(original_file):
            original_file = ida_kernwin.ask_file(0, '*.*', 'Select original file to patch')
        
        if os.path.exists(original_file):
            with open(original_file, 'rb') as f:
                data = list( f.read() )

            patch_file(data, changed_bytes)
        
        else:
            print ('No valid file to patch provided')

    else:
        print ('No changes to patch')

        
print ('---- Running IDA file patching script ----')
main()
print ('---- Script finished ----')