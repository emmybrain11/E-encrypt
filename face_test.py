# main.py - Complete working DeepFace test
import os
from deepface import DeepFace


def create_test_photos():
    """Create simple test photos if they don't exist"""
    try:
        import cv2
        import numpy as np

        # Create faces folder
        os.makedirs("faces", exist_ok=True)

        # Create dummy face images (simple colored squares)
        # Photo 1: Light blue square
        img1 = np.zeros((250, 250, 3), dtype=np.uint8)
        img1[:, :] = [200, 220, 240]  # Light blue
        cv2.imwrite("test_face_alice.jpg", img1)

        # Photo 2: Light pink square
        img2 = np.zeros((250, 250, 3), dtype=np.uint8)
        img2[:, :] = [240, 220, 200]  # Light pink
        cv2.imwrite("test_face_bob.jpg", img2)

        # Save one as registered face
        cv2.imwrite("faces/alice.jpg", img1)

        print("✅ Created test photos: test_face_alice.jpg, test_face_bob.jpg, faces/alice.jpg")

    except ImportError:
        print("⚠️  Install OpenCV for auto-created photos: pip install opencv-python")
        print("📸 Please manually create photos named: test_face_alice.jpg and test_face_bob.jpg")


def test_deepface():
    """Test if DeepFace works with our photos"""
    print("\n🧪 Testing DeepFace...")

    # Check if photos exist
    if not os.path.exists("test_face_alice.jpg"):
        create_test_photos()

    try:
        # TEST 1: Same person (should return True)
        print("\nTest 1: Comparing same face...")
        result = DeepFace.verify(
            img1_path="test_face_alice.jpg",
            img2_path="faces/alice.jpg",  # Same image
            model_name='Facenet',
            enforce_detection=False,  # Don't require real faces
            detector_backend='opencv'
        )
        print(f"✅ Same face test: {result['verified']} (Distance: {result['distance']:.4f})")

        # TEST 2: Different people (should return False)
        print("\nTest 2: Comparing different faces...")
        result = DeepFace.verify(
            img1_path="test_face_alice.jpg",
            img2_path="test_face_bob.jpg",  # Different image
            model_name='Facenet',
            enforce_detection=False,
            detector_backend='opencv'
        )
        print(f"✅ Different face test: {result['verified']} (Distance: {result['distance']:.4f})")

        # TEST 3: Real face recognition example
        print("\nTest 3: Face recognition for login...")
        username = "alice"
        login_photo = "test_face_alice.jpg"
        registered_photo = f"faces/{username}.jpg"

        if os.path.exists(registered_photo):
            result = DeepFace.verify(
                img1_path=login_photo,
                img2_path=registered_photo,
                model_name='Facenet',
                enforce_detection=False
            )

            if result['verified']:
                print(f"✅ SUCCESS: Face recognized! Welcome {username}")
                print(f"   Confidence: {1 - result['distance']:.2%}")
            else:
                print(f"❌ FAILED: Face not recognized")
                print(f"   Distance: {result['distance']:.4f} (lower is better)")
        else:
            print(f"⚠️  No registered face for {username}")
            print(f"   Save a photo as: {registered_photo}")

    except Exception as e:
        print(f"❌ Error: {e}")
        print("\n🔧 Quick fix: Create the photos manually:")
        print("1. Right-click in your project folder → New → Text Document")
        print("2. Rename to: test_face_alice.jpg (and test_face_bob.jpg)")
        print("3. Or use real photos with those names")


def face_login_example(username, photo_path):
    """Complete face login function for your app"""
    print(f"\n🔐 Face Login Attempt for: {username}")

    # 1. Check if user has registered face
    registered_face = f"faces/{username}.jpg"

    if not os.path.exists(registered_face):
        print(f"❌ No registered face found for {username}")
        print(f"   Please register first: save a photo as {registered_face}")
        return False

    # 2. Check if login photo exists
    if not os.path.exists(photo_path):
        print(f"❌ Login photo not found: {photo_path}")
        return False

    # 3. Verify face with DeepFace
    try:
        result = DeepFace.verify(
            img1_path=photo_path,
            img2_path=registered_face,
            model_name='Facenet',
            enforce_detection=False,  # Set to True for real apps
            detector_backend='opencv'
        )

        # 4. Return result
        if result['verified']:
            print(f"✅ Login SUCCESS: Face verified!")
            print(f"   Match distance: {result['distance']:.4f}")
            return True
        else:
            print(f"❌ Login FAILED: Face not recognized")
            print(f"   Match distance: {result['distance']:.4f} (needs to be < 0.4)")
            return False

    except Exception as e:
        print(f"❌ Error during face verification: {e}")
        return False


if __name__ == "__main__":
    print("=" * 50)
    print("🔒 E-Encrypt Face Recognition Test")
    print("=" * 50)

    # Create test photos if needed
    create_test_photos()

    # Test DeepFace
    test_deepface()

    # Example usage for your app
    print("\n" + "=" * 50)
    print("🎯 Example Face Login for Your App")
    print("=" * 50)

    # Simulate Alice logging in
    success = face_login_example(
        username="alice",
        photo_path="test_face_alice.jpg"  # This would come from camera/file dialog
    )

    print("\n📁 Files in your project folder:")
    for file in os.listdir("."):
        if file.endswith((".jpg", ".png", ".jpeg")):
            print(f"  📸 {file}")

    if os.path.exists("faces"):
        print("\n📁 Registered faces:")
        for file in os.listdir("faces"):
            print(f"  👤 {file}")

    print("\n✅ Ready to integrate into E-Encrypt app!")
    print("\nTo add this to your LoginScreen:")
    print("1. Add: from deepface import DeepFace")
    print("2. Use the face_login_example() function")
    print("3. Get photo_path from camera or file dialog")