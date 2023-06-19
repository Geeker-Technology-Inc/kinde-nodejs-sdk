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
 * The CreateOrganizationRequest model module.
 * @module model/CreateOrganizationRequest
 * @version 1
 */
class CreateOrganizationRequest {
    /**
     * Constructs a new <code>CreateOrganizationRequest</code>.
     * @alias module:model/CreateOrganizationRequest
     */
    constructor() { 
        
        CreateOrganizationRequest.initialize(this);
    }

    /**
     * Initializes the fields of this object.
     * This method is used by the constructors of any subclasses, in order to implement multiple inheritance (mix-ins).
     * Only for internal use.
     */
    static initialize(obj) { 
    }

    /**
     * Constructs a <code>CreateOrganizationRequest</code> from a plain JavaScript object, optionally creating a new instance.
     * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
     * @param {Object} data The plain JavaScript object bearing properties of interest.
     * @param {module:model/CreateOrganizationRequest} obj Optional instance to populate.
     * @return {module:model/CreateOrganizationRequest} The populated <code>CreateOrganizationRequest</code> instance.
     */
    static constructFromObject(data, obj) {
        if (data) {
            obj = obj || new CreateOrganizationRequest();

            if (data.hasOwnProperty('name')) {
                obj['name'] = ApiClient.convertToType(data['name'], 'String');
            }
            if (data.hasOwnProperty('feature_flags')) {
                obj['feature_flags'] = ApiClient.convertToType(data['feature_flags'], {'String': 'String'});
            }
            if (data.hasOwnProperty('external_id')) {
                obj['external_id'] = ApiClient.convertToType(data['external_id'], 'String');
            }
            if (data.hasOwnProperty('background_color')) {
                obj['background_color'] = ApiClient.convertToType(data['background_color'], 'String');
            }
            if (data.hasOwnProperty('button_color')) {
                obj['button_color'] = ApiClient.convertToType(data['button_color'], 'String');
            }
            if (data.hasOwnProperty('button_text_color')) {
                obj['button_text_color'] = ApiClient.convertToType(data['button_text_color'], 'String');
            }
            if (data.hasOwnProperty('link_color')) {
                obj['link_color'] = ApiClient.convertToType(data['link_color'], 'String');
            }
        }
        return obj;
    }

    /**
     * Validates the JSON data with respect to <code>CreateOrganizationRequest</code>.
     * @param {Object} data The plain JavaScript object bearing properties of interest.
     * @return {boolean} to indicate whether the JSON data is valid with respect to <code>CreateOrganizationRequest</code>.
     */
    static validateJSON(data) {
        // ensure the json data is a string
        if (data['name'] && !(typeof data['name'] === 'string' || data['name'] instanceof String)) {
            throw new Error("Expected the field `name` to be a primitive type in the JSON string but got " + data['name']);
        }
        // ensure the json data is a string
        if (data['external_id'] && !(typeof data['external_id'] === 'string' || data['external_id'] instanceof String)) {
            throw new Error("Expected the field `external_id` to be a primitive type in the JSON string but got " + data['external_id']);
        }
        // ensure the json data is a string
        if (data['background_color'] && !(typeof data['background_color'] === 'string' || data['background_color'] instanceof String)) {
            throw new Error("Expected the field `background_color` to be a primitive type in the JSON string but got " + data['background_color']);
        }
        // ensure the json data is a string
        if (data['button_color'] && !(typeof data['button_color'] === 'string' || data['button_color'] instanceof String)) {
            throw new Error("Expected the field `button_color` to be a primitive type in the JSON string but got " + data['button_color']);
        }
        // ensure the json data is a string
        if (data['button_text_color'] && !(typeof data['button_text_color'] === 'string' || data['button_text_color'] instanceof String)) {
            throw new Error("Expected the field `button_text_color` to be a primitive type in the JSON string but got " + data['button_text_color']);
        }
        // ensure the json data is a string
        if (data['link_color'] && !(typeof data['link_color'] === 'string' || data['link_color'] instanceof String)) {
            throw new Error("Expected the field `link_color` to be a primitive type in the JSON string but got " + data['link_color']);
        }

        return true;
    }


}



/**
 * The organization's name.
 * @member {String} name
 */
CreateOrganizationRequest.prototype['name'] = undefined;

/**
 * The organization's feature flag settings.
 * @member {Object.<String, module:model/CreateOrganizationRequest.InnerEnum>} feature_flags
 */
CreateOrganizationRequest.prototype['feature_flags'] = undefined;

/**
 * The organization's ID.
 * @member {String} external_id
 */
CreateOrganizationRequest.prototype['external_id'] = undefined;

/**
 * The organization's brand settings - background color.
 * @member {String} background_color
 */
CreateOrganizationRequest.prototype['background_color'] = undefined;

/**
 * The organization's brand settings - button color.
 * @member {String} button_color
 */
CreateOrganizationRequest.prototype['button_color'] = undefined;

/**
 * The organization's brand settings - button text color.
 * @member {String} button_text_color
 */
CreateOrganizationRequest.prototype['button_text_color'] = undefined;

/**
 * The organization's brand settings - link color.
 * @member {String} link_color
 */
CreateOrganizationRequest.prototype['link_color'] = undefined;





/**
 * Allowed values for the <code>inner</code> property.
 * @enum {String}
 * @readonly
 */
CreateOrganizationRequest['InnerEnum'] = {

    /**
     * value: "str"
     * @const
     */
    "str": "str",

    /**
     * value: "int"
     * @const
     */
    "int": "int",

    /**
     * value: "bool"
     * @const
     */
    "bool": "bool"
};



export default CreateOrganizationRequest;

