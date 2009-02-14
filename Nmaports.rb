# Author : FreedomCoder ( Matias Pablo Brutti )
# Email: matiasbrutti@gmail.com
# Created on : February 9, 2009
# License: GPL 3.0
# Description : NMAP output parser that creates a table of  Ports --> IPs. 
# This is helpful to create a list of open ports and their corresponding IP addresses. 


require 'rubygems'
require 'getoptlong'
require 'rexml/document'
@nmap_dir, @nmap_file, @pattern, @output  = nil
opts = GetoptLong.new(
[ '--help', '-h', GetoptLong::NO_ARGUMENT ],
['--dir','-d', GetoptLong::REQUIRED_ARGUMENT ],
['--file','-f', GetoptLong::REQUIRED_ARGUMENT ],
['--pattern','-p', GetoptLong::REQUIRED_ARGUMENT ],
['--output','-o', GetoptLong::REQUIRED_ARGUMENT ]
)

opts.each do |opt, arg|
  case opt
    when '--help':
      # BEGIN OF HELP
      puts "\nHELP for Nmaport\n---------------------\n
      --help, -h
      \tWell I guess you know what this is for (To obtain this Help).\n
      --dir, -d [directory_name]
      \t The root path for the nmap files.\n
      --pattern, -p
      \t The pattern to use to detect file (i.e *client*).\n
      --file, -f [file_name] 
      \tIf we only want one file.\n
      --output, -o
      \tThe output file name.
      Copyright 2009 - FreedomCoder\n"
      #END OF HELP
      exit(0)
    when '--dir':
      if File.exists?(arg)
        @nmap_dir = arg
      else
        puts "Directory not found"
      end
        
    when '--file':
      if File.exists?(arg)
        @nmap_file = arg
      else
        puts "File not found"
      end
    when '--pattern':
      @pattern = arg
    when '--output':
      @output = arg
    else
      puts "Unknown command. Please try again"
     exit(0)
  end
end


# method to read files from directoy ---------------------------------------------------------------

def get_files(dir,name)
  files = Dir["#{dir}/**/#{name || "*"}.xml"]
end

def dir_open_ports(dir)
  arr = []
  dir.each do |doc| 
    arr += open_ports(read_xml(doc))
  end
  arr.uniq.sort
end

def dir_get_ips(dir, ports)
  final_list = {}
  dir.each do |doc|
    puts "Working on #{doc}\n"
    final_list.merge!(get_ips(read_xml(doc),ports)) { |k,o,n| final_list[k] =  (o + n).sort.uniq }
  end
  final_list  
end

# methods to parse XML Nmap output -----------------------------------------------------------------

def read_xml(xml)
  doc = REXML::Document.new(File.read(xml)).root
end

def open_ports(doc)
  out = []
  doc.elements.each('host') do |h|
    h.elements.each('ports/port') do |p|
      if p.elements['state'].attributes['state'] == "open" 
        out << "#{p.attributes['portid']}/#{p.attributes['protocol']}"
      end
    end
  end
  out.uniq.sort
end

def open?(host,port)
  host.elements.each('ports/port') do |p|
    if p.attributes['portid'] == port.split('/')[0] && p.elements['state'].attributes['state'] == "open"
      return true
    end
  end
  false
end

def get_ips(doc,ports)
  open_list = {}
  ports.each do |port|
    a = []
    doc.elements.each('host') do |h|
      if open?(h,port)
        a << h.elements['address'].attributes['addr']
      end
    end
    open_list[port] = a
  end
  open_list
end

#methods to output the data ------------------------------------------------------------------------

def create_csv(list,name=nil)
  out = File.new(name || "output.csv", "w")
  out << "PORT,IP Adressess\n"
  list.each do |k,v|
    out << "#{k},\"#{(v.map { |k| k + "\n" }.to_s).strip}\" \n"
  end
end

def show_data(list)
  puts "PORT\t  IP Adressess\n"
  list.each do |k,v|
    puts "#{k}\t#{(v.map { |k| "        " + k + "\n" }.to_s).strip} \n"
    puts "--------------------------"
  end
end
# Script -------------------------------------------------------------------------------------------
puts "Let's work ..."
lista = {}

if @nmap_dir
  dir_list = get_files(@nmap_dir,@patern)
  ports = dir_open_ports(dir_list)
  lista = dir_get_ips(dir_list, ports)
end

if @nmap_file
  xml_file = read_xml(@nmap_file)
  ports = open_ports(xml_file)
  if lista.empty? 
    lista = get_ips(xml_file,ports)
  else
    lista.merge!(get_ips(xml_file,ports)) do |k,o,n| 
      lista[k] =  (o + n).sort.uniq
    end
  end
end
show_data(lista)
create_csv(lista,@output)
puts "Data written to file #{@output || "output.csv"}"
puts "Bye"
