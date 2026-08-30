import { useState } from "react";

import "./ProjectEdit.css";


function ProjectEdit({
  project,
  onSave,
  onCancel,
}) {

  /* ========================================
     Form State
  ======================================== */

  const [
    name,
    setName,
  ] = useState(
    project?.name || ""
  );


  const [
    description,
    setDescription,
  ] = useState(
    project?.description || ""
  );


  const [
    error,
    setError,
  ] = useState("");


  /* ========================================
     저장
  ======================================== */

  const handleSubmit = (event) => {

    event.preventDefault();


    const trimmedName =
      name.trim();


    const trimmedDescription =
      description.trim();


    /* ======================================
       프로젝트명 검증
    ====================================== */

    if (!trimmedName) {

      setError(
        "프로젝트명을 입력해주세요."
      );

      return;
    }


    setError("");


    /* ======================================
       기존 Project 데이터를 유지하면서

       name / description만 수정
    ====================================== */

    const updatedProject = {
      ...project,

      name:
        trimmedName,

      description:
        trimmedDescription,
    };


    onSave?.(
      updatedProject
    );
  };


  /* ========================================
     Render
  ======================================== */

  return (

    <div className="project-edit">


      {/* ===================================
          Header
      =================================== */}

      <div className="project-edit-header">


        <button
          type="button"
          className="back-button"
          onClick={onCancel}
        >
          ← 상세로 돌아가기
        </button>


        <div className="project-edit-title">

          <h1>
            프로젝트 수정
          </h1>

          <p>
            프로젝트의 기본 정보를 수정합니다.
          </p>

        </div>


      </div>


      {/* ===================================
          Form
      =================================== */}

      <form
        className="project-edit-form"
        onSubmit={handleSubmit}
      >


        {/* =================================
            Error
        ================================= */}

        {
          error && (

            <div className="project-edit-error">

              {
                error
              }

            </div>

          )
        }


        {/* =================================
            프로젝트명
        ================================= */}

        <div className="project-edit-form-group">

          <label htmlFor="project-edit-name">

            프로젝트명

            <span className="required">
              *
            </span>

          </label>


          <input
            id="project-edit-name"
            type="text"
            value={name}
            onChange={
              (event) =>
                setName(
                  event.target.value
                )
            }
            placeholder="프로젝트명을 입력해주세요."
          />

        </div>


        {/* =================================
            설명
        ================================= */}

        <div className="project-edit-form-group">

          <label htmlFor="project-edit-description">
            설명
          </label>


          <textarea
            id="project-edit-description"
            value={description}
            onChange={
              (event) =>
                setDescription(
                  event.target.value
                )
            }
            placeholder="프로젝트에 대한 설명을 입력해주세요."
          />

        </div>


        {/* =================================
            Actions
        ================================= */}

        <div className="project-edit-actions">


          <button
            type="button"
            className="project-edit-cancel-button"
            onClick={onCancel}
          >
            취소
          </button>


          <button
            type="submit"
            className="project-edit-save-button"
          >
            저장
          </button>


        </div>


      </form>


    </div>

  );
}


export default ProjectEdit;