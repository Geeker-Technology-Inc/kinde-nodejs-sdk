/**
 * Kinde Management API
 * Provides endpoints to manage your Kinde Businesses
 *
 * The version of the OpenAPI document: 1
 * Contact: support@kinde.com
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 *
 */

import ApiClient from '../ApiClient';
import Application from './Application';

/**
 * The GetApplicationsResponse model module.
 * @module model/GetApplicationsResponse
 * @version 1
 */
class GetApplicationsResponse {
    /**
     * Constructs a new <code>GetApplicationsResponse</code>.
     * @alias module:model/GetApplicationsResponse
     */
    constructor() { 
        
        GetApplicationsResponse.initialize(this);
    }

    /**
     * Initializes the fields of this object.
     * This method is used by the constructors of any subclasses, in order to implement multiple inheritance (mix-ins).
     * Only for internal use.
     */
    static initialize(obj) { 
    }

    /**
     * Constructs a <code>GetApplicationsResponse</code> from a plain JavaScript object, optionally creating a new instance.
     * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
     * @param {Object} data The plain JavaScript object bearing properties of interest.
     * @param {module:model/GetApplicationsResponse} obj Optional instance to populate.
     * @return {module:model/GetApplicationsResponse} The populated <code>GetApplicationsResponse</code> instance.
     */
    static constructFromObject(data, obj) {
        if (data) {
            obj = obj || new GetApplicationsResponse();

            if (data.hasOwnProperty('code')) {
                obj['code'] = ApiClient.convertToType(data['code'], 'String');
            }
            if (data.hasOwnProperty('message')) {
                obj['message'] = ApiClient.convertToType(data['message'], 'String');
            }
            if (data.hasOwnProperty('organizations')) {
                obj['organizations'] = ApiClient.convertToType(data['organizations'], [Application]);
            }
            if (data.hasOwnProperty('next_token')) {
                obj['next_token'] = ApiClient.convertToType(data['next_token'], 'String');
            }
        }
        return obj;
    }

    /**
     * Validates the JSON data with respect to <code>GetApplicationsResponse</code>.
     * @param {Object} data The plain JavaScript object bearing properties of interest.
     * @return {boolean} to indicate whether the JSON data is valid with respect to <code>GetApplicationsResponse</code>.
     */
    static validateJSON(data) {
        // ensure the json data is a string
        if (data['code'] && !(typeof data['code'] === 'string' || data['code'] instanceof String)) {
            throw new Error("Expected the field `code` to be a primitive type in the JSON string but got " + data['code']);
        }
        // ensure the json data is a string
        if (data['message'] && !(typeof data['message'] === 'string' || data['message'] instanceof String)) {
            throw new Error("Expected the field `message` to be a primitive type in the JSON string but got " + data['message']);
        }
        if (data['organizations']) { // data not null
            // ensure the json data is an array
            if (!Array.isArray(data['organizations'])) {
                throw new Error("Expected the field `organizations` to be an array in the JSON data but got " + data['organizations']);
            }
            // validate the optional field `organizations` (array)
            for (const item of data['organizations']) {
                Application.validateJsonObject(item);
            };
        }
        // ensure the json data is a string
        if (data['next_token'] && !(typeof data['next_token'] === 'string' || data['next_token'] instanceof String)) {
            throw new Error("Expected the field `next_token` to be a primitive type in the JSON string but got " + data['next_token']);
        }

        return true;
    }


}



/**
 * Response code.
 * @member {String} code
 */
GetApplicationsResponse.prototype['code'] = undefined;

/**
 * Response message.
 * @member {String} message
 */
GetApplicationsResponse.prototype['message'] = undefined;

/**
 * @member {Array.<module:model/Application>} organizations
 */
GetApplicationsResponse.prototype['organizations'] = undefined;

/**
 * Pagination token.
 * @member {String} next_token
 */
GetApplicationsResponse.prototype['next_token'] = undefined;






export default GetApplicationsResponse;

