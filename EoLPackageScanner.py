import json
import requests

# Package mapping dictionary
package_mapping = {
    # Node.js Packages
    "npm:@angular/core": "angular",
    "npm:react": "react",
    "npm:vue": "vuejs",
    "npm:lodash": "lodash",
    "npm:express": "express",
    "npm:async": "async",
    "npm:bluebird": "bluebird",
    "npm:body-parser": "body-parser",
    "npm:chalk": "chalk",
    "npm:commander": "commander",
    "npm:dotenv": "dotenv",
    "npm:eslint": "eslint",
    "npm:jest": "jest",
    "npm:mongoose": "mongoose",
    "npm:mocha": "mocha",
    "npm:moment": "moment",
    "npm:nodemon": "nodemon",
    "npm:webpack": "webpack",
    "npm:typescript": "typescript",
    "npm:@babel/core": "babel",
    "npm:@nestjs/core": "nestjs",
    "npm:@testing-library/react": "testing-library",
    "npm:rxjs": "rxjs",
    "npm:next": "nextjs",
    "npm:gatsby": "gatsby",
    
    # .NET Packages
    "nuget:Microsoft.AspNetCore.App": "aspnetcore",
    "nuget:Newtonsoft.Json": "newtonsoftjson",
    "nuget:Serilog": "serilog",
    "nuget:EntityFramework": "entityframework",
    "nuget:AutoMapper": "automapper",
    "nuget:NLog": "nlog",
    "nuget:Castle.Core": "castle-core",
    "nuget:Dapper": "dapper",
    "nuget:Swashbuckle.AspNetCore": "swashbuckle",
    "nuget:Polly": "polly",
    "nuget:FluentValidation": "fluentvalidation",
    "nuget:MediatR": "mediatR",
    "nuget:IdentityServer4": "identityserver4",
    "nuget:Hangfire": "hangfire",
    "nuget:NUnit": "nunit",
    "nuget:Moq": "moq",
    "nuget:Microsoft.Extensions.Logging": "microsoft-extensions-logging",
    "nuget:Microsoft.EntityFrameworkCore": "entityframeworkcore",
    "nuget:Xunit": "xunit",
    "nuget:Microsoft.AspNetCore.Identity": "aspnetcore-identity",
    "nuget:Microsoft.Extensions.Configuration": "microsoft-extensions-configuration",
    "nuget:Microsoft.Extensions.DependencyInjection": "microsoft-extensions-dependencyinjection",
    "nuget:Microsoft.AspNetCore.Authentication.JwtBearer": "aspnetcore-authentication-jwtbearer",
    "nuget:Microsoft.AspNetCore.Mvc": "aspnetcore-mvc",
    "nuget:Microsoft.AspNetCore.Http": "aspnetcore-http"
}

def normalize_package_name(name):
    if name.lower().startswith("npm:@"):
        return package_mapping.get(name.lower(), name.lower().replace("npm:@", "").replace("/", "-"))
    elif name.lower().startswith("nuget:"):
        return package_mapping.get(name.lower(), name.lower().replace("nuget:", "").replace(".", "-"))
    else:
        return package_mapping.get(name.lower(), name.lower())

def get_endoflife_data(product):
    response = requests.get(f"https://endoflife.date/api/{product}.json")
    if response.status_code == 200:
        return response.json()
    else:
        return None

def get_all_products():
    response = requests.get("https://endoflife.date/api/all.json")
    if response.status_code == 200:
        return response.json()
    else:
        return []
    
def extract_major_version(version):
    # Extract the major version (the part before the first dot)
    return version.split('.')[0]

def match_major_version(version1, version2):
    major_version1 = extract_major_version(version1)
    major_version2 = extract_major_version(version2)
    return major_version1 == major_version2

def normalize_version(version):
    # Remove leading non-numeric characters
    normalized_version = ''.join(c for c in version if c.isdigit() or c == '.')
    # Ensure it starts with a digit
    if normalized_version and not normalized_version[0].isdigit():
        normalized_version = normalized_version[1:]
    return normalized_version

def check_eol_packages(sbom_file):
    with open(sbom_file, 'r') as file:
        sbom_data = json.load(file)

    packages = sbom_data.get('packages', [])
    eol_packages = []
    valid_products = get_all_products()

    for package in packages:
        name = package.get('name')
        version_info = package.get('versionInfo')
        version_info = normalize_version(version_info)
        if not name or not version_info:
            continue

        normalized_name = normalize_package_name(name)
        if normalized_name in valid_products:
            endoflife_data = get_endoflife_data(normalized_name)
            if endoflife_data:
                for cycle in endoflife_data:
                    if (match_major_version(cycle.get('latest'), version_info) and cycle.get('eol')):
                        eol_packages.append({
                            "name": name,
                            "version": version_info,
                            "eol_date": cycle['eol'],
                        })
                        break

    return eol_packages

if __name__ == "__main__":
    import sys
    sbom_file = sys.argv[1]
    eol_packages = check_eol_packages(sbom_file)
    with open('/sbom/eol_packages.json', 'w') as file:
        json.dump(eol_packages, file)
