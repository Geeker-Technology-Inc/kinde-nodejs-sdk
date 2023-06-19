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

(function(root, factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD.
    define(['expect.js', process.cwd()+'/src/index'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    factory(require('expect.js'), require(process.cwd()+'/src/index'));
  } else {
    // Browser globals (root is window)
    factory(root.expect, root.KindeManagementApi);
  }
}(this, function(expect, KindeManagementApi) {
  'use strict';

  var instance;

  beforeEach(function() {
    instance = new KindeManagementApi.FeatureFlagsApi();
  });

  var getProperty = function(object, getter, property) {
    // Use getter method if present; otherwise, get the property directly.
    if (typeof object[getter] === 'function')
      return object[getter]();
    else
      return object[property];
  }

  var setProperty = function(object, setter, property, value) {
    // Use setter method if present; otherwise, set the property directly.
    if (typeof object[setter] === 'function')
      object[setter](value);
    else
      object[property] = value;
  }

  describe('FeatureFlagsApi', function() {
    describe('createFeatureFlag', function() {
      it('should call createFeatureFlag successfully', function(done) {
        //uncomment below and update the code to test createFeatureFlag
        //instance.createFeatureFlag(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('deleteFeatureFlag', function() {
      it('should call deleteFeatureFlag successfully', function(done) {
        //uncomment below and update the code to test deleteFeatureFlag
        //instance.deleteFeatureFlag(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
    describe('updateFeatureFlag', function() {
      it('should call updateFeatureFlag successfully', function(done) {
        //uncomment below and update the code to test updateFeatureFlag
        //instance.updateFeatureFlag(function(error) {
        //  if (error) throw error;
        //expect().to.be();
        //});
        done();
      });
    });
  });

}));
