import {
  useState,
} from "react";

import "./ProjectEdit.css";


function ProjectEdit({
  project,
  onCancel,
  onSave,
}) {

  /*
   * ========================================
   * 기존 프로젝트 정보를 초기값으로 사용
   * ========================================
   */
  const [
    formData,
    setFormData,
  ] = useState({

    name:
      project.name,

    description:
      project.description || "",

    language:
      project.language,

    sourceType:
      project.sourceType || "upload",

    repositoryUrl:
      project.repositoryUrl || "",

    internalPath:
      project.internalPath || "",

  });


  /*
   * ========================================
   * 새로 교체할 파일
   *
   * 기존 파일은 project.sourceFileName으로
   * 확인하고,
   *
   * 사용자가 새 파일을 선택했을 때만
   * sourceFile에 File 객체가 들어간다.
   * ========================================
   */
  const [
    sourceFile,
    setSourceFile,
  ] = useState(null);


  /*
   * 오류 메시지
   */
  const [
    error,
    setError,
  ] = useState("");


  /*
   * ========================================
   * 일반 입력값 변경
   * ========================================
   */
  const handleChange = (
    e
  ) => {

    const {
      name,
      value,
    } = e.target;


    setFormData(
      (prev) => ({

        ...prev,

        [name]:
          value,

      })
    );
  };


  /*
   * ========================================
   * 새로운 소스 파일 선택
   * ========================================
   */
  const handleFileChange = (
    e
  ) => {

    const file =
      e.target.files[0];


    if (!file) {

      setSourceFile(
        null
      );

      return;
    }


    setSourceFile(
      file
    );
  };


  /*
   * ========================================
   * 수정 완료
   * ========================================
   */
  const handleSubmit = (
    e
  ) => {

    e.preventDefault();

    setError("");


    /*
     * 프로젝트 이름 검사
     */
    if (
      !formData.name.trim()
    ) {

      setError(
        "프로젝트 이름을 입력해주세요."
      );

      return;
    }


    /*
     * ======================================
     * 소스 유형별 검사
     * ======================================
     */


    /*
     * 파일 업로드
     *
     * 기존 파일도 없고
     * 새 파일도 선택하지 않았다면 오류
     */
    if (
      formData.sourceType === "upload" &&
      !project.sourceFileName &&
      !sourceFile
    ) {

      setError(
        "소스 파일을 선택해주세요."
      );

      return;
    }


    /*
     * Repository
     */
    if (
      formData.sourceType === "repository" &&
      !formData.repositoryUrl.trim()
    ) {

      setError(
        "Repository URL을 입력해주세요."
      );

      return;
    }


    /*
     * 내부 경로
     */
    if (
      formData.sourceType === "internal" &&
      !formData.internalPath.trim()
    ) {

      setError(
        "내부 소스 경로를 입력해주세요."
      );

      return;
    }


    /*
     * ======================================
     * 수정된 프로젝트 생성
     * ======================================
     */
    const updatedProject = {

      ...project,

      name:
        formData.name,

      description:
        formData.description,

      language:
        formData.language,

      sourceType:
        formData.sourceType,

    };


    /*
     * ======================================
     * 파일 업로드 방식
     * ======================================
     */
    if (
      formData.sourceType === "upload"
    ) {

      /*
       * 새 파일을 선택했다면
       * 파일명 교체
       *
       * 선택하지 않았다면
       * 기존 파일명 유지
       */
      updatedProject.sourceFileName =
        sourceFile
          ? sourceFile.name
          : project.sourceFileName;


      /*
       * 다른 소스 방식 데이터 제거
       */
      updatedProject.repositoryUrl =
        "";

      updatedProject.internalPath =
        "";
    }


    /*
     * ======================================
     * Repository 방식
     * ======================================
     */
    if (
      formData.sourceType === "repository"
    ) {

      updatedProject.repositoryUrl =
        formData.repositoryUrl.trim();


      updatedProject.sourceFileName =
        "";

      updatedProject.internalPath =
        "";
    }


    /*
     * ======================================
     * 내부 경로 방식
     * ======================================
     */
    if (
      formData.sourceType === "internal"
    ) {

      updatedProject.internalPath =
        formData.internalPath.trim();


      updatedProject.sourceFileName =
        "";

      updatedProject.repositoryUrl =
        "";
    }


    /*
     * 부모 컴포넌트에
     * 수정된 프로젝트 전달
     */
    onSave(
      updatedProject
    );
  };


  return (
    <div className="project-edit">


      {/* =============================
          상단
      ============================= */}

      <div className="project-edit-header">

        <button
          type="button"
          className="back-button"
          onClick={
            onCancel
          }
        >
          ← 상세로
        </button>


        <div className="project-edit-title">

          <h2>
            프로젝트 수정
          </h2>

          <p>
            프로젝트 정보와 분석 대상
            소스를 수정할 수 있습니다.
          </p>

        </div>

      </div>



      {/* =============================
          수정 Form
      ============================= */}

      <form
        className="project-edit-form"
        onSubmit={
          handleSubmit
        }
      >


        {/* 프로젝트 이름 */}

        <div className="project-edit-form-group">

          <label
            htmlFor="edit-name"
          >
            프로젝트 이름

            <span className="required">
              *
            </span>
          </label>


          <input
            id="edit-name"
            name="name"
            type="text"

            value={
              formData.name
            }

            onChange={
              handleChange
            }
          />

        </div>



        {/* 프로젝트 설명 */}

        <div className="project-edit-form-group">

          <label
            htmlFor="edit-description"
          >
            프로젝트 설명
          </label>


          <textarea
            id="edit-description"
            name="description"
            rows="5"

            value={
              formData.description
            }

            onChange={
              handleChange
            }
          />

        </div>



        {/* 분석 언어 */}

        <div className="project-edit-form-group">

          <label
            htmlFor="edit-language"
          >
            분석 언어

            <span className="required">
              *
            </span>
          </label>


          <select
            id="edit-language"
            name="language"

            value={
              formData.language
            }

            onChange={
              handleChange
            }
          >

            <option value="Java">
              Java
            </option>

            <option value="JavaScript">
              JavaScript
            </option>

            <option value="Python">
              Python
            </option>

          </select>

        </div>



        {/* =================================
            소스 유형
        ================================= */}

        <div className="project-edit-form-group">

          <label
            htmlFor="edit-source-type"
          >
            소스 유형

            <span className="required">
              *
            </span>
          </label>


          <select
            id="edit-source-type"
            name="sourceType"

            value={
              formData.sourceType
            }

            onChange={
              handleChange
            }
          >

            <option value="upload">
              파일 업로드
            </option>

            <option value="repository">
              저장소 연계
            </option>

            <option value="internal">
              내부 경로
            </option>

          </select>

        </div>



        {/* =================================
            파일 업로드 방식
        ================================= */}

        {
          formData.sourceType === "upload" && (

            <div className="project-edit-form-group">

              <label
                htmlFor="edit-source-file"
              >
                소스 파일
              </label>


              {
                project.sourceType === "upload" &&
                project.sourceFileName && (

                  <div className="current-source-file">

                    <span className="current-source-label">
                      현재 파일
                    </span>

                    <span className="current-source-value">
                      {
                        project.sourceFileName
                      }
                    </span>

                  </div>

                )
              }


              <input
                id="edit-source-file"
                type="file"

                onChange={
                  handleFileChange
                }
              />


              {
                sourceFile && (

                  <p className="new-source-file">

                    새 파일: {
                      sourceFile.name
                    }

                  </p>

                )
              }


              <p className="source-help-text">
                새 파일을 선택하지 않으면
                기존 소스 파일을 유지합니다.
              </p>

            </div>

          )
        }



        {/* =================================
            Repository 방식
        ================================= */}

        {
          formData.sourceType ===
            "repository" && (

            <div className="project-edit-form-group">

              <label
                htmlFor="edit-repository-url"
              >
                Repository URL

                <span className="required">
                  *
                </span>
              </label>


              <input
                id="edit-repository-url"

                name="repositoryUrl"

                type="text"

                value={
                  formData.repositoryUrl
                }

                onChange={
                  handleChange
                }

                placeholder=
                  "Repository URL을 입력하세요."
              />

            </div>

          )
        }



        {/* =================================
            내부 소스 경로
        ================================= */}

        {
          formData.sourceType ===
            "internal" && (

            <div className="project-edit-form-group">

              <label
                htmlFor="edit-internal-path"
              >
                내부 소스 경로

                <span className="required">
                  *
                </span>
              </label>


              <input
                id="edit-internal-path"

                name="internalPath"

                type="text"

                value={
                  formData.internalPath
                }

                onChange={
                  handleChange
                }

                placeholder=
                  "/source/project"
              />

            </div>

          )
        }



        {/* =================================
            오류 메시지
        ================================= */}

        {
          error && (

            <p className="project-edit-error">
              {error}
            </p>

          )
        }



        {/* =================================
            버튼
        ================================= */}

        <div className="project-edit-actions">

          <button
            type="button"

            className="project-edit-cancel-button"

            onClick={
              onCancel
            }
          >
            취소
          </button>


          <button
            type="submit"

            className="project-edit-save-button"
          >
            수정 완료
          </button>

        </div>


      </form>

    </div>
  );
}


export default ProjectEdit;