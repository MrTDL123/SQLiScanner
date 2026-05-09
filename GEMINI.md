+ Không được phép "Premature optimization", code nếu như không có quá ảnh hưởng tới hiệu năng thì luôn ưu tiên code đơn giản và dễ nhìn.
+ Vì là sinh viên nên tôi hay hỏi phương pháp tích hợp các thuật toán để xử lý vấn đề, nên hãy bày ra những phương pháp khả thi và ưu tiên các phương pháp có tốc độ O(n) tương đối và dễ hiểu.
+ Đừng lạm dụng thư viện C/C++ (Native/Interop) ở những vòng lặp quá nhanh. Nếu một thao tác nhỏ giọt được gọi hàng triệu lần, hãy cân nhắc viết nó bằng C# thuần để tránh phí chuyển đổi (Marshalling).

+ Áp dụng triệt để "Zero-Allocation":

	Dùng struct thay vì class cho các object dữ liệu nhỏ sống trong thời gian ngắn.

	Dùng Span<T> và Memory<T> khi cần cắt chuỗi hoặc thao tác với mảng thay vì tạo ra chuỗi/mảng mới.

	Tái sử dụng object bằng ObjectPool<T> (ví dụ: tái sử dụng các kết nối DB, các buffer mạng).

+ Hạn chế interface và virtual methods ở "Hot Path": Đoạn code nào chạy nhiều nhất (như vòng lặp xử lý, xử lý dòng stream), hãy gọi trực tiếp hàm tĩnh (static) hoặc hàm cụ thể (concrete type) để JIT Compiler có thể Inline chúng.

+ Thiết kế định hướng dữ liệu (Data-Oriented Design): Cố gắng dùng mảng các struct liền kề nhau thay vì các danh sách các class lộn xộn trên Heap. Nó sẽ giúp CPU của ta phát huy 100% sức mạnh thay vì lãng phí thời gian đi tìm dữ liệu.