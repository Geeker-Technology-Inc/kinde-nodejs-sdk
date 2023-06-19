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

/**
 * The CreateUserRequestProfile model module.
 * @module model/CreateUserRequestProfile
 * @version 1
 */
class CreateUserRequestProfile {
    /**
     * Constructs a new <code>CreateUserRequestProfile</code>.
     * Basic information required to create a user.
     * @alias module:model/CreateUserRequestProfile
     */
    constructor() { 
        
        CreateUserRequestProfile.initialize(this);
    }

    /**
     * Initializes the fields of this object.
     * This method is used by the constructors of any subclasses, in order to implement multiple inheritance (mix-ins).
     * Only for internal use.
     */
    static initialize(obj) { 
    }

    /**
     * Constructs a <code>CreateUserRequestProfile</code> from a plain JavaScript object, optionally creating a new instance.
     * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
     * @param {Object} data The plain JavaScript object bearing properties of interest.
     * @param {module:model/CreateUserRequestProfile} obj Optional instance to populate.
     * @return {module:model/CreateUserRequestProfile} The populated <code>CreateUserRequestProfile</code> instance.
     */
    static constructFromObject(data, obj) {
        if (data) {
            obj = obj || new CreateUserRequestProfile();

            if (data.hasOwnProperty('given_name')) {
                obj['given_name'] = ApiClient.convertToType(data['given_name'], 'String');
            }
            if (data.hasOwnProperty('family_name')) {
                obj['family_name'] = ApiClient.convertToType(data['family_name'], 'String');
            }
        }
        return obj;
    }

    /**
     * Validates the JSON data with respect to <code>CreateUserRequestProfile</code>.
     * @param {Object} data The plain JavaScript object bearing properties of interest.
     * @return {boolean} to indicate whether the JSON data is valid with respect to <code>CreateUserRequestProfile</code>.
     */
    static validateJSON(data) {
        // ensure the json data is a string
        if (data['given_name'] && !(typeof data['given_name'] === 'string' || data['given_name'] instanceof String)) {
            throw new Error("Expected the field `given_name` to be a primitive type in the JSON string but got " + data['given_name']);
        }
        // ensure the json data is a string
        if (data['family_name'] && !(typeof data['family_name'] === 'string' || data['family_name'] instanceof String)) {
            throw new Error("Expected the field `family_name` to be a primitive type in the JSON string but got " + data['family_name']);
        }

        return true;
    }


}



/**
 * User's first name.
 * @member {String} given_name
 */
CreateUserRequestProfile.prototype['given_name'] = undefined;

/**
 * User's last name.
 * @member {String} family_name
 */
CreateUserRequestProfile.prototype['family_name'] = undefined;






export default CreateUserRequestProfile;

