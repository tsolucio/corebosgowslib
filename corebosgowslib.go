// Package corebosgowslib coreBOS Web service access library
/*************************************************************************************************
 * Copyright 2018 JPL TSolucio, S.L. -- This file is a part of TSOLUCIO coreBOS.
 * The MIT License (MIT)
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 * and associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
 * NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *************************************************************************************************/
package corebosgowslib

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type cbConnectionType struct {
	servertime  float64
	expiretime  string
	token       string
	serviceuser string
	servicekey  string
	sessionid   string
	userid      string
}

var cbConnection cbConnectionType
var cbURL = "/webservice.php"
var netClient = &http.Client{
	Timeout: time.Second * 10,
}
var queryRestulColumns = make(map[int]string)

// SetURL of the coreBOS application you want to connect to
func SetURL(cburl string) {
	if cburl[len(cburl)-1:] == "/" {
		cbURL = cburl + "webservice.php"
	} else {
		cbURL = cburl + "/webservice.php"
	}
}

func doChallenge(username string) (bool, error) {
	v := url.Values{
		"operation": {"getchallenge"},
		"username":  {username},
	}
	_, dat, e := docbCall("GET", v)
	if e == nil && dat["success"] == true {
		rdo := dat["result"].(map[string]interface{})
		cbConnection.servertime = rdo["serverTime"].(float64)
		cbConnection.expiretime = rdo["expireTime"].(string)
		cbConnection.token = rdo["token"].(string)
		return true, nil
	}
	return false, e
}

// DoLogin connects to coreBOS and tries to validate the given user.
// true or false will be returned depending on the result of the validation
func DoLogin(username string, userAccesskey string, withpassword bool) (bool, error) {
	dc, err := doChallenge(username)
	if dc == false {
		return false, err
	}
	v := url.Values{
		"operation": {"login"},
		"username":  {username},
	}
	if withpassword == true {
		v.Set("accessKey", cbConnection.token+userAccesskey)
	} else {
		v.Set("accessKey", getMD5Hash(cbConnection.token+userAccesskey))
	}
	_, dat, e := docbCall("POST", v)
	if e == nil && dat["success"] == true {
		rdo := dat["result"].(map[string]interface{})
		cbConnection.serviceuser = username
		cbConnection.servicekey = userAccesskey
		cbConnection.sessionid = rdo["sessionName"].(string)
		cbConnection.userid = rdo["userId"].(string)
		return true, nil
	}
	if e == nil {
		wserr := dat["error"].(map[string]interface{})
		return false, errors.New(wserr["code"].(string) + ": " + wserr["message"].(string))
	}
	return false, e
}

// DoLogout disconnects from coreBOS.
// returns true or false depending on the result
func DoLogout() (bool, error) {
	v := url.Values{
		"operation":   {"logout"},
		"sessionName": {cbConnection.sessionid},
	}
	_, dat, e := docbCall("POST", v)
	if e == nil && dat["success"] == true {
		return true, nil
	}
	if e == nil {
		wserr := dat["error"].(map[string]interface{})
		return false, errors.New(wserr["code"].(string) + ": " + wserr["message"].(string))
	}
	return false, e
}

// DoQuery retrieves records using a specilized query language
// returns the set of records and columsn obtained from the query
func DoQuery(query string) (interface{}, error) {
	// query must end in ; so we make sure
	q := strings.Trim(query, " ;") + ";"
	v := url.Values{
		"operation":   {"query"},
		"sessionName": {cbConnection.sessionid},
		"query":       {q},
	}
	_, dat, e := docbCall("GET", v)
	if e == nil && dat["success"] == true {
		rdos := dat["result"].([]interface{})
		if len(rdos) > 0 {
			idx := 0
			for col := range rdos[0].(map[string]interface{}) {
				queryRestulColumns[idx] = col
				idx++
			}
		} else {
			queryRestulColumns = make(map[int]string)
		}
		return dat["result"], nil
	}
	empty := make(map[string]interface{})
	if e == nil {
		wserr := dat["error"].(map[string]interface{})
		return empty, errors.New(wserr["code"].(string) + ": " + wserr["message"].(string))
	}
	return empty, e
}

// GetResultColumns returns the column names of the last query
func GetResultColumns() map[int]string {
	return queryRestulColumns
}

// DoListTypes returns a list of available Modules for the connected user
// filtered by those that contain a field of the given type(s). If no type is
// given all accessible modules will be returned
func DoListTypes(fieldTypeList []string) (map[string]string, error) {
	ftl, _ := json.Marshal(fieldTypeList)
	v := url.Values{
		"operation":     {"listtypes"},
		"sessionName":   {cbConnection.sessionid},
		"fieldTypeList": {string(ftl)},
	}
	_, dat, e := docbCall("GET", v)
	if e == nil && dat["success"] == true {
		rdos := dat["result"].(map[string]interface{})
		types := make(map[string]string)
		for _, mod := range rdos["types"].([]interface{}) {
			mname := mod.(string)
			types[mname] = mname
		}
		return types, nil
	}
	empty := make(map[string]string)
	if e == nil {
		wserr := dat["error"].(map[string]interface{})
		return empty, errors.New(wserr["code"].(string) + ": " + wserr["message"].(string))
	}
	return empty, e
}

// DoDescribe gets all the details of a Module's permissions and fields
func DoDescribe(module string) (map[string]interface{}, error) {
	v := url.Values{
		"operation":   {"describe"},
		"sessionName": {cbConnection.sessionid},
		"elementType": {module},
	}
	_, dat, e := docbCall("GET", v)
	if e == nil && dat["success"] == true {
		return dat["result"].(map[string]interface{}), nil
	}
	empty := make(map[string]interface{})
	if e == nil {
		wserr := dat["error"].(map[string]interface{})
		return empty, errors.New(wserr["code"].(string) + ": " + wserr["message"].(string))
	}
	return empty, e
}

// DoRetrieve details of a record.
func DoRetrieve(record string) (map[string]interface{}, error) {
	v := url.Values{
		"operation":   {"retrieve"},
		"sessionName": {cbConnection.sessionid},
		"id":          {record},
	}
	_, dat, e := docbCall("GET", v)
	if e == nil && dat["success"] == true {
		return dat["result"].(map[string]interface{}), nil
	}
	empty := make(map[string]interface{})
	if e == nil {
		wserr := dat["error"].(map[string]interface{})
		return empty, errors.New(wserr["code"].(string) + ": " + wserr["message"].(string))
	}
	return empty, e
}

// DoCreate adds new records to the application
func DoCreate(module string, valuemap map[string]interface{}) (map[string]interface{}, error) {
	// Assign record to logged in user if not specified
	_, exists := valuemap["assigned_user_id"]
	if exists == false {
		valuemap["assigned_user_id"] = cbConnection.userid
	}
	vals, _ := json.Marshal(valuemap)
	v := url.Values{
		"operation":   {"create"},
		"sessionName": {cbConnection.sessionid},
		"elementType": {module},
		"element":     {string(vals)},
	}
	_, dat, e := docbCall("POST", v)
	if e == nil && dat["success"] == true {
		return dat["result"].(map[string]interface{}), nil
	}
	empty := make(map[string]interface{})
	if e == nil {
		wserr := dat["error"].(map[string]interface{})
		return empty, errors.New(wserr["code"].(string) + ": " + wserr["message"].(string))
	}
	return empty, e
}

// DoUpdate updates the given record with the new values.
// ALL mandatory fields MUST be present
func DoUpdate(module string, valuemap map[string]interface{}) (map[string]interface{}, error) {
	// Assign record to logged in user if not specified
	_, exists := valuemap["assigned_user_id"]
	if exists == false {
		valuemap["assigned_user_id"] = cbConnection.userid
	}
	vals, _ := json.Marshal(valuemap)
	v := url.Values{
		"operation":   {"update"},
		"sessionName": {cbConnection.sessionid},
		"elementType": {module},
		"element":     {string(vals)},
	}
	_, dat, e := docbCall("POST", v)
	if e == nil && dat["success"] == true {
		return dat["result"].(map[string]interface{}), nil
	}
	empty := make(map[string]interface{})
	if e == nil {
		wserr := dat["error"].(map[string]interface{})
		return empty, errors.New(wserr["code"].(string) + ": " + wserr["message"].(string))
	}
	return empty, e
}

// DoRevise updates the given record with the new values.
// mandatory fields do not have to be present
func DoRevise(module string, valuemap map[string]interface{}) (map[string]interface{}, error) {
	// Assign record to logged in user if not specified
	_, exists := valuemap["assigned_user_id"]
	if exists == false {
		valuemap["assigned_user_id"] = cbConnection.userid
	}
	vals, _ := json.Marshal(valuemap)
	v := url.Values{
		"operation":   {"revise"},
		"sessionName": {cbConnection.sessionid},
		"elementType": {module},
		"element":     {string(vals)},
	}
	_, dat, e := docbCall("POST", v)
	if e == nil && dat["success"] == true {
		return dat["result"].(map[string]interface{}), nil
	}
	empty := make(map[string]interface{})
	if e == nil {
		wserr := dat["error"].(map[string]interface{})
		return empty, errors.New(wserr["code"].(string) + ": " + wserr["message"].(string))
	}
	return empty, e
}

// DoDelete eliminates the record with the given ID
func DoDelete(record string) (bool, error) {
	v := url.Values{
		"operation":   {"delete"},
		"sessionName": {cbConnection.sessionid},
		"id":          {record},
	}
	_, dat, e := docbCall("POST", v)
	if e == nil && dat["success"] == true {
		rdo := dat["result"].(map[string]interface{})
		if rdo["status"].(string) == "successful" {
			return true, nil
		} else {
			return false, errors.New("Unexpected DELETE error")
		}
	}
	if e == nil {
		wserr := dat["error"].(map[string]interface{})
		return false, errors.New(wserr["code"].(string) + ": " + wserr["message"].(string))
	}
	return false, e
}

// DoInvoke custom operations
// param String method Name of the webservice to invoke
// param Object type null or parameter values to method
// param String POST/GET
func DoInvoke(method string, params map[string]interface{}, typeofcall string) (map[string]interface{}, error) {
	v := url.Values{
		"operation":   {method},
		"sessionName": {cbConnection.sessionid},
	}
	for idx, val := range params {
		if v.Get(idx) == "" {
			v.Set(idx, val.(string))
		}
	}
	_, dat, e := docbCall(typeofcall, v)
	if e == nil && dat["success"] == true {
		return dat["result"].(map[string]interface{}), nil
	}
	empty := make(map[string]interface{})
	if e == nil {
		wserr := dat["error"].(map[string]interface{})
		return empty, errors.New(wserr["code"].(string) + ": " + wserr["message"].(string))
	}
	return empty, e
}

// DoGetRelatedRecords will retrieve all related records of the given record that belong to the given related module
func DoGetRelatedRecords(record string, module string, relatedModule string, queryParameters map[string]interface{}) ([]interface{}, error) {
	params, _ := json.Marshal(queryParameters)
	v := url.Values{
		"operation":       {"getRelatedRecords"},
		"sessionName":     {cbConnection.sessionid},
		"id":              {record},
		"module":          {module},
		"relatedModule":   {relatedModule},
		"queryParameters": {string(params)},
	}
	_, dat, e := docbCall("POST", v)
	if e == nil && dat["success"] == true {
		rdo := dat["result"].(map[string]interface{})
		return rdo["records"].([]interface{}), nil
	}
	var empty []interface{}
	if e == nil {
		wserr := dat["error"].(map[string]interface{})
		return empty, errors.New(wserr["code"].(string) + ": " + wserr["message"].(string))
	}
	return empty, e
}

// DoSetRelated establishes a relation between records
// param relateThisID string ID of record we want to be related with other records
// param withTheseIds array of IDs to relate to the first parameter
func DoSetRelated(relateThisID string, withTheseIds []string) (bool, error) {
	params, _ := json.Marshal(withTheseIds)
	v := url.Values{
		"operation":      {"SetRelation"},
		"sessionName":    {cbConnection.sessionid},
		"relate_this_id": {relateThisID},
		"with_these_ids": {string(params)},
	}
	_, dat, e := docbCall("POST", v)
	if e == nil && dat["success"] == true {
		return dat["result"].(bool), nil
	}
	if e == nil {
		wserr := dat["error"].(map[string]interface{})
		return false, errors.New(wserr["code"].(string) + ": " + wserr["message"].(string))
	}
	return false, e
}

// DoLoginPage get HTML for the Login page
func DoLoginPage(template string, language string, csrf string) (string, error) {
	v := url.Values{
		"operation":   {"getLoginPage"},
		"sessionName": {cbConnection.sessionid},
		"template":    {template},
		"language":    {language},
		"csrf":        {csrf},
	}
	_, dat, e := docbCall("GET", v)
	if e == nil && dat["success"] == true {
		return dat["result"].(string), nil
	}
	if e == nil {
		wserr := dat["error"].(map[string]interface{})
		return "", errors.New(wserr["code"].(string) + ": " + wserr["message"].(string))
	}
	return "", e
}

///////////////////////////////////////////////////////

func docbCall(typeofcall string, params url.Values) (bool, map[string]interface{}, error) {
	empty := make(map[string]interface{})
	var resp *http.Response
	var err error
	body := bytes.NewBufferString(params.Encode())
	if strings.ToUpper(typeofcall[0:]) == "POST" {
		resp, err = netClient.Post(cbURL, "application/x-www-form-urlencoded", body)
	} else {
		resp, err = netClient.Get(cbURL + "?" + body.String())
	}
	if err != nil {
		return false, empty, err
	}
	b, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return false, empty, err
	}

	var dat map[string]interface{}
	e := json.Unmarshal(b, &dat)
	return true, dat, e
}

func getMD5Hash(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}
