import re
import json
import traceback
from collections import defaultdict
import xml.etree.cElementTree as ET

# OSM Tag element categories  
lower = re.compile(r'^([a-z0-9]|_)*$', re.IGNORECASE)
lower_colon = re.compile(r'^([a-z0-9]|_)*:([a-z0-9]|_)*$', re.IGNORECASE)
problemchars = re.compile(r'[=\+/&<>;\'"\?%#$@\,\. \t\r\n]', re.IGNORECASE)
postcode_validator = re.compile(r'^[0-9]{6}$')
bengaluru_validator = re.compile(r'bengaluru|bangalore', re.IGNORECASE)


def validate_postcode(postcode):
    '''
        Validate that the postcode is a 6 digit string. If found in any known 
        format, convert it to the correct form.
          Args:
                   postcode (str): raw postcode value from OSM
          Returns:
                   str: cleaned postcode in xxxxxx format
    '''
    if postcode_validator.search(postcode):
        # Valid postcode XXXXXX
        return postcode
    else:
        if re.search('([0-9]{3})[ \t]*([0-9]{3})',postcode):
            # Postcode split as XXX XXX 
            t = re.search('([0-9]{3})[ \t]*([0-9]{3})', postcode)
            return ''.join(t.groups())
        elif re.search('^[0-9]{2}$',postcode):
            # Shorthand for bangalore postcode 5600XX
            return '5600' + ''.join(re.search('^[0-9]{2}$', postcode).group())
    return postcode


def validate_city(city_name):
    '''
        Bangalore got renamed to Bengaluru a few years back. Thus there are
        entries in OSM which are still using the old name Bangalore.
        This function replaces the old names to 'Bengaluru' from all its 
        various forms in which its stored in the DB right now.

        The function returns the existing city name, which sometimes
        also has street address in them. 

        Args:
                  city_name (str): raw city name value from OSM
        Returns:
                  tuple(str): cleaned city name as a tuple with the city name 
                                    and the remaining address as street address 

        
    '''
    if city_name == 'Bengaluru':
        return (city_name, None)
    else:
        if bengaluru_validator.search(city_name):
            return ('Bengaluru', re.sub(bengaluru_validator, '', city_name))
    return ('Bengaluru', city_name)


def validate_addr(addr_dict):
    '''
        Function to validate the address sub-document
         Args:
                   addr_dict (dict): address dictionary from OSM
         Returns:
                   dict: cleaned address dictionary to store in JSON 
    '''
    drop_items = []
    add_items = []
    
    for addr_tag in addr_dict:
        if addr_tag == 'city':
            city_name_list = validate_city(addr_dict[addr_tag])[0]
            if city_name_list[1] == None:
                addr_dict[addr_tag] = city_name_list[0]
            elif 'street' not in addr_dict:
                add_items.append(('street', city_name_list[1])) 
            else:
                for i in range(1,10):
                    # Ignore this entry if more than 10 entries exist
                    # for street address
                    if 'street_' + str(i) not in addr_dict:
                      add_items.append(('street' + str(i), city_name_list[1]))
                    
        elif addr_tag == 'postcode':
            addr_dict[addr_tag] = validate_postcode(addr_dict[addr_tag])
        elif addr_tag == 'housenumber' and not re.search('[0-9\/]+', \
            addr_dict[addr_tag]):
                # if the housenumber is not a valid one remove the entry.
                drop_items.append(addr_tag)
        elif addr_tag == 'number':
            # if the addr:number is present but not addr:housenumber convert 
            # number to the standard housenumber 
            if 'housenumber' not in addr_dict:
                add_items.append(('housenumber', addr_dict[addr_tag]))

    # Find elements that have no data and drop them
    for item in addr_dict:
        if addr_dict[item] == None:
            drop_items.append(item)
    
    # Drop elements which are not valid
    for item in drop_items:
        addr_dict.pop(item, None)
    
    # Add elements discovered within the loop
    for item in add_items:
        addr_dict[item[0]] = item[1]

    return addr_dict 


def validate_phone(phone_num):
    '''
        Convert phone numbers from their various forms and translate it into
        a common accepted format
        
        +91-80-XXXXXXXX for landlines or +91-XXXXXXXXXX for mobiles 

         Args:
                   phone_num (str): raw phone number value from OSM
        Returns:
                   str: cleaned phone number in formats shown above
    '''
    phone_list =  [num for num in phone_num.split(';')]
    # Split on ';' and '/' to get split multiple phone entries in the same tag
    temp_num = []
    temp_repl = ''
    for num in phone_list:
        if '/' in num:
            temp_num = num.split('/')
            temp_repl = num
        if ',' in num:
            temp_num = num.split(',')
            temp_repl = num
    if temp_repl != '':
        phone_list.remove(temp_repl)
        for num in temp_num:
            phone_list.append(num)
    
    # Validate individual phone numbers
    temp_num = []
    
    for num in phone_list:
        stripped_num = num.lstrip().rstrip()
        if re.search(r'(\+?91-80-[0-9]{8})|(\+91-[0-9]{10})', stripped_num):
          # No issues. Matches the basic format of +91-80-xxxxxxxx (Landlines)
          temp_num.append(stripped_num)
        elif re.search(r'\+?91[ ]*80[ ]*([0-9]{8})', stripped_num):
          # +91 80 XXXXXXXX
          temp_re = re.search(r'\+?91[ ]*80[ ]*([0-9]{8})', stripped_num)
          temp_num.append(
              '+91-80-' + temp_re.groups()[0])
        elif re.search(r'\+?91[ ]*80[ ]*([0-9]{4}) ([0-9]{4})', stripped_num):
          # +91 80 XXXX XXXX
          temp_re = re.search(r'\+?91[ ]*80[ ]*([0-9]{4}) ([0-9]{4})', 
                                stripped_num)
          temp_num.append(
              '+91-80-' + temp_re.groups()[0] + temp_re.groups()[1])
        elif re.search(r'^([0-9]{8}$)', stripped_num):
          # +91XXXXX XXXXX
          temp_num.append(
              '+91-80-' + re.search(r'^([0-9]{8})$', stripped_num).groups()[0])
        elif re.search(r'^([0-9]{8}$)', stripped_num):
          # XXXXXXXX
          temp_num.append(
              '+91-80-' + re.search(r'^([0-9]{8})$', stripped_num).groups()[0])
        elif re.search(r'080[ |-]*([0-9]{8})', stripped_num):
          # 080 XXXXXXXX
          temp_re = re.search(r'080[ |-]*([0-9]{8})', stripped_num)
          temp_num.append(
              '+91-80-' + temp_re.groups()[0])
        elif re.search(r'\+?91[ ]*([0-9]{10})', stripped_num):
          #+91 XXXXX XXXXX
          temp_re = re.search(r'\+?91[ ]*([0-9]{10})', stripped_num)
          temp_num.append(
              '+91-' + temp_re.groups()[0])
        elif re.search(r'^\+?91([0-9]{10})', stripped_num):
          # +91XXXXX XXXXX
          temp_num.append(
             '+91-' + re.search(r'\+?91([0-9]{10})', stripped_num).groups()[0])
        elif re.search(r'^([0-9]{10})$', stripped_num):
          # XXXXX XXXXX
          temp_num.append(
              '+91-' + re.search(r'^([0-9]{10})$', stripped_num).groups()[0])
        else:
            temp_num.append(num)
        
    return temp_num


def shape_element(element):
    '''
        Function that iterates over each top level node in the OSM XML
        and returns the python dictionary representation for the element
            Args:
                   element (str): XML element from OSM
          Returns:
                   dict: python dictionary for the OSM element after cleaning
    '''
    node = {}

    if element.tag in ["way", "node", "relation"]:
        if element.tag == "way":
            node['node_refs'] = []
            for elm in element.iter('nd'):
                node['node_refs'].append(elm.attrib['ref'])
        if 'visible' in element.attrib:
            node['visible'] = element.attrib['visible']
        node['id'] = element.attrib['id']
        node['type'] = element.tag
        node['created'] = {}
        node['created']['version'] = element.attrib['version']
        node['created']['uid'] = element.attrib['uid']
        node['created']['user'] = element.attrib['user']
        node['created']['timestamp'] = element.attrib['timestamp']
        node['created']['changeset'] = element.attrib['changeset']
        if element.tag == 'node':
            node['pos'] = [float(element.attrib['lat']), 
                            float(element.attrib['lon'])]
        
        # Variables to aggregate fields which are going to be dicts
        phone_list = []

        for elm in element.iter('tag'):
            # Tag key which are having only lower case characters
            if lower.search(elm.attrib['k']):
                # Store phone numbers in a list. 
                # Converting many entries as phone, phone_1, etc. to a list
                if 'phone' in elm.attrib['k']:
                    phone_list += validate_phone(elm.attrib['v'])
                else:
                    node[elm.attrib['k']] = elm.attrib['v']
            
            # Tags which have problem characters. Drop these tags
            elif problemchars.search(elm.attrib['k']):
                continue
            
            #  If tag name has colon seperated fields
            elif lower_colon.search(elm.attrib['k']):
                current_tag_split = elm.attrib['k'].split(':')[0] 
                if current_tag_split not in node:
                    node[current_tag_split] = {}
                elif type(node[current_tag_split]) in [type('str'), \
                  type(u'unicode')]:
                    node[current_tag_split] =  \
                                {current_tag_split : node[current_tag_split]}
                
                try:
                    node[current_tag_split][elm.attrib['k'].split(':')[1]] =\
                                                 unicode(elm.attrib['v'])
                except Exception as e:
                    # Just in case some odd entries come in. 
                    # For Bengaluru OSM no issues are present
                    print e, type(node[current_tag_split])
                    print type(elm.attrib['k'].split(':')[1])
                   
        
        # Expand aggregate variables for the final <node> dict
        if len(phone_list) > 0:
            node['phone'] = phone_list

        # Validate other variables which are dicts, like addr, building.
        if 'addr' in node:
            node['addr'] = validate_addr(node['addr'])

        return node
    else:
        return None


def process_file(osm_file):
    '''
        Process the given OSM XML file and store the converted JSON array into
        a file 
         Args:
                   osm_file (str): File name of the OSM XML file
         Returns:
                   None
    '''
    count = 0
    file_count = 30
    data = []
    
    # get an iterable
    context = ET.iterparse(osm_file, events=("start", "end"))

    # turn it into an iterator
    context = iter(context)

    # get the root element
    event, root = context.next()
    
    for event, element in context:
        if event == "end" and element.tag in ['way', 'node', 'relation']:    
            process_data = shape_element(element) 
            if process_data is not None:
                data.append(process_data)
                count += 1
                # Dump 1 million records into a new file
                if len(data) == 1000000:
                    with open('result' + str(file_count) + '.json', 'w') as fp:
                        json.dump(data, fp)
                    file_count += 1
                    # Reset data
                    data = []
        root.clear()
    # Dump the remaining records
    with open('result' + str(file_count) + '.json', 'w') as fp:
        json.dump(data, fp)
    print 'Processed {0} "way", "node" and "relation" records'.format(count)


# Process the OSM XML file and generate the JSOn array for MongoDB to ingest. 
if __name__ == '__main__':
    process_file('sample.osm')