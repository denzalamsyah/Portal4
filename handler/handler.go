package handler

import (
	"a21hc3NpZ25tZW50/client"
	"a21hc3NpZ25tZW50/model"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"
)

var UserLogin = make(map[string]model.User)

// DESC: func Auth is a middleware to check user login id, only user that already login can pass this middleware
func Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("user_login_id")
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(model.ErrorResponse{Error: err.Error()})
			return
		}

		if _, ok := UserLogin[c.Value]; !ok || c.Value == "" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(model.ErrorResponse{Error: "user login id not found"})
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, "userID", c.Value)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// DESC: func AuthAdmin is a middleware to check user login role, only admin can pass this middleware
func AuthAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("user_login_role")
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "user login role not found"})
			return
		}

		if cookie.Value != "admin" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "user login role not Admin"})
			return
		}

		next.ServeHTTP(w, r)
	})
	}

func Login(w http.ResponseWriter, r *http.Request) {
	// baca request body
	body, err := ioutil.ReadAll(r.Body)

	if err != nil{
		panic(err)
	}

	var user model.User
	// parse request body ke json
	err = json.Unmarshal(body, &user)
	if err != nil{
		panic(err)
	}
	// cek apaka id dan name tidak diisi/kosong
	if user.ID == "" || user.Name == ""{
		w.WriteHeader(400)
		w.Write([]byte(`{"error":"ID or name is empty"}`))
	}

	// embaca file users.txt
	file, err := ioutil.ReadFile("data/users.txt")
	if err != nil{
		panic(err)
	}

	// memisakan datayang ada di users.txt dengan garis baru
	userList := strings.Split(string(file), "\n")
	
	
	// menemukan user di userlist
	for _, s := range userList {
		fields := strings.Split(s, "_")
		if fields[0] == user.ID && fields[1] == user.Name{
			// Login berhasil
            // Set cookie
            http.SetCookie(w, &http.Cookie{Name: "user_login_id", Value: user.ID})
            http.SetCookie(w, &http.Cookie{Name: "user_login_role", Value: fields[2]})

            // Simpan data user ke dalam UserLogin
            UserLogin[user.ID] = model.User{ID: fields[0], Name: fields[1], Role: fields[2]}

            // Response
            w.WriteHeader(http.StatusOK)
            fmt.Fprintf(w, `{"username":"%s","message":"login success"}`, user.ID)
            return
		}
	}

	w.WriteHeader(400)
	w.Write([]byte(`{"error":"user not found"}`))


}

func Register(w http.ResponseWriter, r *http.Request) {
	// membaca request body
	body, err := ioutil.ReadAll(r.Body)
	if err != nil{
		panic(err)
	}

	// parse request body ke json
	var user model.User
	err1 := json.Unmarshal(body, &user)
	if err1 != nil{
		panic(err1)
	}
	// cek jika ID, name, atau study kosong
	
	if user.ID == "" || user.Name == "" || user.Role == "" || user.StudyCode == ""{
		w.WriteHeader(400)
		w.Write([]byte(`{"error":"ID, name, study code or role is empty"}`))
		return
	}

	// pastikan role yang diberikan anya admin atau user
	if user.Role != "admin" && user.Role != "user" {
		http.Error(w, `{"error":"role must be admin or user"}`, http.StatusBadRequest)
		return
	}
	// membuka file list-study.txt untuk cek study code
	file, err := ioutil.ReadFile("data/list-study.txt")
	if err != nil{
		panic(err)
	}

	// memisakan setiap data yang ada dengan garis baru
	studyList := strings.Split(string(file), "\n")

	var found bool
	// menemukan studi progra di studi list
	for _, s := range studyList {
		if strings.Contains(s, user.StudyCode) { // jika ketemu maka kembalikan true
			found = true
			break
		}
	}
	if !found { //jika tidak ketemu
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"error":"study code not found"}`))
		return
	}

	users, err := ioutil.ReadFile("data/users.txt")
	if err != nil{
		panic(err)
	}

	if strings.Contains(string(users), user.ID){
		http.Error(w, `{"error":"user id already exist"}`, 400)
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"username":"` + user.ID + `","message":"register success"}`)) 

	newUser := user.ID + "_" + user.Name + "_" + user.StudyCode  + "_" + user.Role + "\n"
	err2 := os.WriteFile("data/users.txt", []byte(newUser), 0644)
	if  err2 != nil{
			panic(err2)
	}
	
}

func Logout(w http.ResponseWriter, r *http.Request) {

	// cek apakah user sudah login
	cookie, err := r.Cookie("user_login_id")
	
	if err != nil {
		if err == http.ErrNoCookie {
			// Jika cookie tidak di set, return unauthorized status
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"user login id not found"}`))
			return
		}
		// Untuk jenis error lainnya, return bad request status
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	 // Hapus data user dari UserLogin
	 delete(UserLogin, cookie.Value)
	 // Kita ubah nilai cookie dari user menjadi kosong dan tetapkan waktu expired  menjadi waktu saat ini
		http.SetCookie(w, &http.Cookie{
			Name:    "session_token",
			Value:   "",
			Expires: time.Now(),
		})
 
	 // Response
	 w.WriteHeader(http.StatusOK)
	 fmt.Fprintf(w, `{"username":"%s","message":"logout success"}`, cookie.Value)
}

func GetStudyProgram(w http.ResponseWriter, r *http.Request) {

	  // Cek user sudah login
	  _, err := r.Cookie("user_login_id")
	  if err != nil {
		  w.WriteHeader(http.StatusUnauthorized)
		  fmt.Fprintf(w, `{"error":"user login id not found"}`)
		  return
	  }
  
		// buka file
		file, err := os.Open("data/list-study.txt")
		if err != nil {
			panic(err)
		}
		defer file.Close()

		fileread, err := ioutil.ReadAll(file)
		if err != nil {
			panic(err)
		}
  
	  // Baca isi file dan konversi ke slice of struct StudyProgram
	  var studyPrograms []model.StudyData
	  isi := strings.Split(string(fileread), "\n")
	  for _, line := range isi {
		// split baris menjadi kode dan nama program
		parts := strings.Split(line, "_")
		code := parts[0]
		name := strings.Join(parts[1:], " ")
		// buat instance struct Program
		program := model.StudyData{
			Code: code,
			Name: name,
		}
		// tambahkan instance ke slice programs
		studyPrograms = append(studyPrograms, program)
	}
  
	  // Konversi slice of struct StudyProgram ke JSON dan kirim sebagai response
	  w.Header().Set("Content-Type", "application/json")
	  w.WriteHeader(http.StatusOK)
	  json.NewEncoder(w).Encode(studyPrograms)
}

func AddUser(w http.ResponseWriter, r *http.Request) {
	// Cek user sudah login
	_, err := r.Cookie("user_login_id")
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"error":"user login id not found"}`)
		return
	}

	roleCookie, err := r.Cookie("user_login_role")

	if err != nil || roleCookie.Value != "admin"{
		w.WriteHeader(401)
		w.Write([]byte(`{"error":"user login role not Admin"}`))
		return
	}

	var user model.User
	err = json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		panic(err)
	}

	if user.ID == "" || user.Name == "" || user.StudyCode == ""{
		w.WriteHeader(400)
		w.Write([]byte(`{"error":"ID, name, or study code is empty"}`))
	}
	// membuka file list-study.txt untuk cek study code
	file, err := ioutil.ReadFile("data/list-study.txt")
	if err != nil{
		panic(err)
	}

	studyList := strings.Split(string(file), "\n")

	var found bool
	for _, s := range studyList {
		if strings.Contains(s, user.StudyCode) {
			found = true
			break
		}
	}
	if !found {
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"error":"study code not found"}`))
		return
	}
	
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"username":"` + user.ID + `","message":"add user success"}`))

	newUser := user.ID + "_" + user.Name + "_" + user.StudyCode + "\n"
	err2 := os.WriteFile("data/users.txt", []byte(newUser), 0644)
	if  err2 != nil{
		panic(err2)
	} 
	fmt.Println("success write data")
}

func DeleteUser(w http.ResponseWriter, r *http.Request) {
	// Cek user sudah login
	_, err := r.Cookie("user_login_id")
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"error":"user login id not found"}`)
		return
	}

	roleCookie, err := r.Cookie("user_login_role")

	if err != nil || roleCookie.Value != "admin"{
		w.WriteHeader(401)
		w.Write([]byte(`{"error":"user login role not Admin"}`))
		return
	}

		// Check query parameter
		id := r.URL.Query().Get("id")
		if id == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"user id is empty"}`))
			return
		}

		// baca file 
		file, err := ioutil.ReadFile("data/users.txt")
		if err != nil{
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("File tidak bisa di baca"))
		}

		// uraikan isi file ke dalam menjadi struct slice
		var users = make([]model.User, 0)
		// memecah isi dari file dengan garis baru
		lines := strings.Split(string(file), "\n")
		for _, line := range lines{
			
			if line != ""{ // jika isi file tidak kosong
				parts := strings.Split(line, "_")
				user := model.User{
					ID: parts[0],
					Name: parts[1],
					StudyCode: parts[2],
				}

				users = append(users, user)
			}
		}

		// Mencari indeks user yang ingin dihapus
		index := -1 // nilai default
		for i, line := range lines {
			if strings.Contains(line, id) { // jika line mangandung nilai id yang diberikan
				index = i // maka set nilai i sama dengan nilai index (nilai yang akan dihapus)
				break
			}
		}
	
		// Mengembalikan pesan error jika user tidak ditemukan
		if index == -1 {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"user id not found"}`))
			return
		}

		// Menghapus user dari slice
		users = append(users[:index], users[index+1:]...)

		// menyimpan users data yang baru ke file
		lines = make([]string, 0)
		for _, user := range users {
			line := user.ID + "_" + user.Name + "_" + user.StudyCode + "\n"
			lines = append(lines, line)
		}


		data := []byte(strings.Join(lines, "")) // konversi menjadi slice byte dengan string tanpa pemisah
		err = ioutil.WriteFile("data/users.txt", data, 0644) // menyimpan pembaruan
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("tidak bisa menyimpan pembaruan"))
			return
		}
	
		// Send success response
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"username":"` + id + `","message":"delete success"}`))


}

// DESC: Gunakan variable ini sebagai goroutine di handler GetWeather
var GetWetherByRegionAPI = client.GetWeatherByRegion

func GetWeather(w http.ResponseWriter, r *http.Request) {
	// var listRegion = []string{"jakarta", "bandung", "surabaya", "yogyakarta", "medan", "makassar", "manado", "palembang", "semarang", "bali"}

	// DESC: dapatkan data weather dari 10 data di atas menggunakan goroutine
	// TODO: answer here
}




