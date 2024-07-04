#include "SharedComponents/RuleProvider/DLP/Conditions/CommonDLPConditions.hpp"

#include "Modules/DLP/Operations/DLPOperationOnePath.hpp"
#include "Modules/DLP/Operations/DLPOperationTwoPath.hpp"
//#include "Modules/DLP/Operations/RylanFunc.hpp"
#include <cstdlib> // for getenv

CommonDLPConditions::CommonDLPConditions( const nlohmann::json &j )
{
    if ( j.contains( "fileExtension" ) )
        fileExtension_ = std::make_optional( j[ "fileExtension" ].get< std::string >() );

    if ( j.contains( "pathPrefix" ) )
        pathPrefix_ = std::make_optional( j[ "pathPrefix" ].get< std::string >() );

    if ( j.contains( "pathRegex" ) )
        pathRegex_ = std::make_optional( j[ "pathRegex" ].get< std::regex >() );
    
    if ( j.contains( "isSensitive" ) )
        isSensitive_ = std::make_optional( j[ "isSensitive" ].get< bool >() );
}

/* virtual */ bool CommonDLPConditions::CheckConditions( const DLPOperation &operation )
{
    bool doesMatch = true;

    if ( operation.Operation() == DLPOperationType::FileTransfer ) {
        const auto &castedOp = static_cast< const DLPOperationTwoPath & >( operation );

        if ( fileExtension_.has_value() )
            doesMatch =
                doesMatch && ( castedOp.SourcePath().Path().extension() == fileExtension_.value() );

        if ( pathPrefix_.has_value() )
            doesMatch =
                doesMatch && ( std::string_view{ castedOp.SourcePath().Path().c_str() }.starts_with(
                                 pathPrefix_.value() ) );

        if ( pathRegex_.has_value() )
            doesMatch = doesMatch && ( std::regex_match( castedOp.SourcePath().Path().string(),
                                                         pathRegex_.value() ) );
        if ( isSensitive_.has_value() )
            doesMatch = doesMatch && isSensitive(castedOp.SourcePath().Path().string());
    }
    else {
        const auto &castedOp = static_cast< const DLPOperationOnePath & >( operation );

        if ( fileExtension_.has_value() ) 
            doesMatch =
                doesMatch && ( castedOp.Path().Path().extension() == fileExtension_.value() );

        if ( pathPrefix_.has_value() )
            doesMatch =
                doesMatch && ( std::string_view{ castedOp.Path().Path().c_str() }.starts_with(
                                 pathPrefix_.value() ) );

        if ( pathRegex_.has_value() )
            doesMatch = 
                doesMatch && ( std::regex_match( castedOp.Path().Path().string(), pathRegex_.value() ) );

        if ( isSensitive_.has_value() )
            doesMatch = 
                    doesMatch && isSensitive(castedOp.Path().Path().string());      
    }

    return doesMatch;
}

bool CommonDLPConditions::isSensitive(const std::string &file) {
    // Read extended attributes (xattrs) from file
    std::string command = "getfattr -d user.sensitive -d user.financialdata -d user.healthdata " + file;
    std::string result = exec(command.c_str());
    if (result.find("No such attribute") != std::string::npos) {
        return false;
    } else {
        return true;
    }
}