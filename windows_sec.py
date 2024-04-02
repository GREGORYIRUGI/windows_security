

"""
This code gets all installed softwares,firmware,operating system and  drivers. It outputs their versions,vendor and names.

The result of softwares and drivers installed are stored in a csv file,for easy export  to table formart.
  
"""
import winreg
import wmi
import csv
import platform
"""
function to retrieves information about installed software from a specific registry hive.
 Returns:
    A list of dictionaries containing software information (name, version, publisher)
"""
def get_installed_software(hive, access_flag=0):
  """
  Args:
      hive: The Windows registry hive to access (e.g., winreg.HKEY_LOCAL_MACHINE).
      access_flag: Optional flag for access rights (defaults to 0).
  """
  
  registry_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
  software_list = []

  try:
    with winreg.ConnectRegistry(None, hive) as reg:
      with winreg.OpenKey(reg, registry_key, 0, winreg.KEY_READ | access_flag) as key:
        num_subkeys = winreg.QueryInfoKey(key)[0]
        for i in range(num_subkeys):
          software = {}
          try:
            subkey_name = winreg.EnumKey(key, i)
            with winreg.OpenKey(key, subkey_name) as subkey:
              software["name"] = winreg.QueryValueEx(subkey, "DisplayName")[0]
              try:
                software["version"] = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
              except EnvironmentError:
                software["version"] = "undefined"
              try:
                software["publisher"] = winreg.QueryValueEx(subkey, "Publisher")[0]
              except EnvironmentError:
                software["publisher"] = "undefined"
          except EnvironmentError:
            continue
          software_list.append(software)
  except EnvironmentError:
    print("A system error have occurred")

  return software_list

# Get software list from different hives
local_machine_32bit = get_installed_software(winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY)
local_machine_64bit = get_installed_software(winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY)
current_user_software = get_installed_software(winreg.HKEY_CURRENT_USER)
# Combine results of software from different  hives
all_software_list = local_machine_32bit + local_machine_64bit + current_user_software

for software in all_software_list:
   print('Name=%s, Version=%s, Publisher=%s' % (software['name'], software['version'], software['publisher']))

# function tto get operating system information
def get_os_info():
   info = platform.uname()
   return info.system,info.release

# function to get firmware information
def get_firmware():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, "SYSTEM\\BIOS")
        version, _ = winreg.QueryValueEx(key, "BIOSVersion")
        return ("BIOS", version)
    except FileNotFoundError:
        return ("BIOS", "Unavailable")
# Getting all drivers inatlled in the system
def get_available_drivers():
    # initializing an empty list to hold drivers if available
    drivers = []
    c = wmi.WMI()
    for driver in c.Win32_PnPSignedDriver():
        drivers.append((driver.Description,driver.DriverVersion,driver.Manufacturer))
    return drivers

print("\n Drivers installed in the machine")
print("driver name \t version \tmanufacturer")
for driver,version,manufucturer in get_available_drivers():
    print(f"{driver}:{version}:{manufucturer}")

# creating a csv file to store software information
with open("software_report.csv", "w", newline="") as csvfile:
    header = ["name", "version", "publisher"]
    writer = csv.DictWriter(csvfile, fieldnames=header)
    writer.writeheader()

    # Write software information to the CSV file
    writer.writerows(all_software_list)

# Create a new CSV file for drivers
with open("drivers_report.csv", "w", newline="") as csvfile:
    header = ["Driver Name", "Version", "Manufacturer"]
    writer = csv.DictWriter(csvfile, fieldnames=header)
    writer.writeheader()

    # Write driver information to the CSV file
    drivers_data = [{"Driver Name": driver, "Version": version, "Manufacturer": manufuncturer} for driver, version, manufuncturer in get_available_drivers()]
    writer.writerows(drivers_data)
 
os_name,os_version = get_os_info()
print("Operating syatem name\t",os_name,"\t version ,installed:\t",os_version)



conn = wmi.WMI()
# create a csv output to store processes flagged as genuine
with open("process_info.csv", "w", newline="") as csvfile:
    fieldnames = ["ProcessID", "HandleCount", "Name"]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()

    # Iterate through processes and write to CSV
    for process in conn.Win32_Process():
        writer.writerow({
            "ProcessID": process.ProcessID,
            "HandleCount": process.HandleCount,
            "Name": process.Name
        })
        
# create a csv output to store processes flagged as genuine 
with open("unusual.csv","w",newline="")as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["State","StartMode","Name","DisplayName"])
    for service in conn.Win32_Service(StartMode="Auto", State="Running"):
        writer.writerow([service.State, service.StartMode, service.Name, service.DisplayName])
        print(service.State, service.StartMode, service.Name, service.DisplayName)